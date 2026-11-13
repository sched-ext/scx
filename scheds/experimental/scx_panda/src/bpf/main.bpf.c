// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// scx_panda -- A SCHED_EXT SCHEDULER BUILT FROM DISCARDED IDEAS AND UNSPENT
// POTENTIAL
//
// EVERYTHING THAT DECIDES LIVES HERE. THE RUST SIDE LOADS THE PROGRAM, SIZES
// AND FILLS THE TOPOLOGY TABLES, AND READS COUNTERS.
//
// ARCHITECTURE:
//   SELECT_CPU IDLE FAST PATH -> PER-CPU DSQ (ADMISSION-BOUNDED, STEALABLE)
//   ENQUEUE TIER 1 IDLE FOUND -> THAT IDLE CPU'S PER-CPU DSQ (WARM)
//   ENQUEUE TIER 2 WARM-ANCHOR -> last_cpu PER-CPU DSQ
//   ENQUEUE TIER 3 FALLBACK    -> A REQUEUE ON ITS OWN CPU'S LANE
//   DISPATCH -> SWEEP, AGED LANE, OWN SEAT, SEAT STEAL, OWN LANE, LANE STEAL,
//               KEEP
//   TICK     -> PER-CPU SOJOURN (LOCAL + ROTATING SCAN) + PREEMPTION
//   STOPPING -> THE RUN HABIT: ONE EWMA OF SERVICE PER RUN, READ AS A PRICE
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
// CPU, AND THE TIME AWAKE PAST WHICH A RESIDENT READS AS ONE THAT DOES NOT
// SLEEP (seat_spent). TAU-DERIVED IN apply_tau_scaling() VIA K_LAG_CAP, CLAMPED
// [8MS, 80MS]; 13.3MS AT THE 12C REFERENCE. NOT AN ORDERING BOUND --
// task_deadline() RETURNS THE ARRIVAL STAMP AND READS NOTHING ELSE. THE VALUE
// BELOW IS A FALLBACK HELD ONLY UNTIL THE FIRST CPU-0 TICK DERIVES THE REAL ONE.
static u64 lag_cap_ns = 40000000ULL;

// THE SWEEP'S AND THE TICK SCAN'S WINDOWS. EACH ROTATES ONE SEAT A CLOCK STEP
// (2^20 ns, 1.05 ms) OVER ITS BUDGET OF SEATS, AND STARTED FROM THE CLOCK ALONE
// EVERY CPU HOLDS THE SAME WINDOW: A SEAT IS OUT OF IT FOR
// (nr_cpu_ids - BUDGET) STEPS A ROTATION, 4.2 ms OF THE SWEEP'S AT 12 CPUs AND
// 126 ms AT 128, PAST lag_cap_ns's OWN CEILING ON THE SWEEP THAT ENFORCES IT.
// SO THE CPUs SPLIT, BY THEIR NUMBER, INTO AS MANY WINDOWS SPACED EVENLY ROUND
// THE MACHINE AS KEEP A SEAT OUT OF ALL OF THEM NO LONGER THAN lag_cap_ns: ONE
// AT 12 CPUs, WHERE THE CLOCK'S OWN ROTATION ALREADY DOES, THREE AT 32 AND
// NINE AT 128. ANY CPU OF A WINDOW SWEEPS IT.
// A WINDOW A CPU, EVERY SEAT IN EIGHT WINDOWS AT ONCE, WAS MEASURED AT 12 CPUs:
// 22 PERCENT MORE RESCUES AND DISPATCHES UNDER A STANDING BACKLOG AND 1 TO 2
// PERCENT OF fork-thread's WALL, FOR 22 us OF contended's JOB WAKE p99.
// SET IN apply_tau_scaling(). A STRIDE OF 0 IS THE ONE WINDOW.
#define BOUND_SWEEP_BUDGET 8
#define TICK_SCAN_BUDGET   4
static u32 sweep_win_count = 1;
static u32 sweep_win_stride;
static u32 scan_win_count = 1;
static u32 scan_win_stride;

#define SLICE_MIN_NS 100000     // 100US FLOOR
// HOW MANY LIVE CoDel TARGETS A STANDING TASK MAY HOLD A CPU FOR. THIS IS THE
// BOUND A WAITER PAYS WHEN IT LANDS ON A BUSY CPU.
#define SLICE_STANDING_TARGETS  4ULL

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

// WHAT THE LOADER WRITES AFTER LOAD, AT TOPOLOGY DETECT AND ON HOTPLUG. ONE
// STRUCT WITH A NON-ZERO INITIALISER SO IT LANDS IN .data, WHICH THE POST-LOAD
// WRITER REACHES; A ZERO INITIALISER WOULD PLACE IT IN .bss.
//   generation            ADVANCED BY THE LOADER AFTER EVERY OTHER FIELD AND
//                         EVERY TABLE OF ONE TOPOLOGY IS WRITTEN. 0 = UNWRITTEN,
//                         THE INIT FALLBACK CONSTANTS STAND. apply_tau_scaling()
//                         RE-DERIVES ON A NEW ONE
//   tau_ns                THE TOPOLOGY TIME CONSTANT
//   codel_eq_ns           THE OSCILLATOR'S EQUILIBRIUM, A POSITION IN THE BAND
//   nr_domains            DISTINCT L3 DOMAINS; MORE THAN ONE ARMS THE TIGHT SEAT
//   affinity_domain_peers HOW MANY affinity_rank SLOTS STAY INSIDE A CPU'S OWN
//                         DOMAIN, THE MINIMUM OVER CPUs FLOORED AT 1. THE RANK
//                         IS SORTED BY R_eff ASCENDING, SO THIS ALONE DECIDES
//                         WHETHER find_idle_by_affinity MAY LEAVE THE DOMAIN
struct panda_topo {
	u64 generation;
	u64 tau_ns;
	u64 codel_eq_ns;
	u32 nr_domains;
	u32 affinity_domain_peers;
};
volatile struct panda_topo topo = {
	.nr_domains = 1,
	.affinity_domain_peers = 3,
};

// THE BASE KNOB SET, DERIVED FROM tau IN apply_tau_scaling(). THE INIT VALUES
// STAND ONLY UNTIL tau ARRIVES. NO USERSPACE WRITER. NOT static: LLVM SPLITS
// AN INTERNAL AGGREGATE INTO SCALARS WHILE BTF KEEPS THE STRUCT, AND THE
// KERNEL REFUSES THE .data DATASEC ON THE SIZE MISMATCH.
struct tuning_knobs knobs_g = {
	.slice_ns = 1000000,
	.batch_slice_ns = 20000000,
	.codel_thresh_ns = 5000000,
};
#define K_SLICE_CAP_Q16     9830u   // 0.15
#define K_BATCH_CAP_Q16    98304u   // 1.5
#define K_SOJOURN_Q16       9830u   // 0.15
#define SLICE_BASE_NS    1000000ULL
#define BATCH_BASE_NS   20000000ULL

// THE RUN HABIT. avg_run_ns IS AN EWMA OF THE SERVICE A TASK TAKES PER RUN,
// FED IN stopping() FROM sum_exec_runtime, alpha 1/8, SEEDED ON THE FIRST
// SAMPLE, THE SAMPLE CLAMPED TO EWMA_SAMPLE_CAP_TARGETS LIVE TARGETS. IT IS
// READ AS A PRICE AND NEVER AS A CLASS: seat_wait() TAKES THE RESIDENT'S HABIT
// AS THE BOUND ON WHAT IT HAS LEFT WHILE IT RUNS INSIDE IT.
#define EWMA_SHIFT 3
#define EWMA_SAMPLE_CAP_TARGETS 4
#define EWMA_HIST_BUCKETS 16

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
//   cut_pid               A SEAT'S ONLY: THE PID THE LATEST CUT ONTO IT WAS FOR.
//                         WRITTEN BY THE CUT BESIDE ITS ARRIVAL, ON THE LINE THE
//                         ARRIVAL ALREADY DIRTIES. SEE CUT_SELF_KICK_NS
struct queue_clock {
	u64 arrivals;
	u64 departures;
	u64 progress_ns;
	u64 last_sojourn_ns;
	u64 next_act;
	u64 acts;
	s32 cut_pid;
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
// THE CLASS SPLIT THE DOMAIN QUEUE MADE BY ROUTING, KEPT ON EACH CPU. WITHOUT
// IT A HOG'S REQUEUE SORTED AHEAD OF EVERY LATER WAKE ON ITS CPU AND ipc's PIPE
// p99 READ 3,003 us AGAINST 15.
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

// THE KERNEL'S ONLINE MASK, MIRRORED: FILLED IN init() AND KEPT BY cpu_online()
// AND cpu_offline(). nr_cpu_ids COUNTS POSSIBLE CPUs, SO A RANGE TEST PASSES A
// CPU THAT IS OFFLINE, AND A TASK'S MASK KEEPS ITS OFFLINE CPUs TOO. AN OFFLINE
// CPU DISPATCHES NOTHING: A TASK ON ITS SEAT WAITS FOR ANOTHER CPU TO TAKE IT,
// AND AN INSERT ON ITS LOCAL DSQ IS BOUNCED BY THE KERNEL
// (SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE). ONE BYTE A CPU, WRITTEN ONLY ON HOTPLUG,
// WHERE THE KERNEL'S MASK COSTS A KFUNC PAIR A TEST.
static bool cpu_up[MAX_CPUS];

// A CPU A TASK MAY BE SEATED ON: INSIDE nr_cpu_ids AND ONLINE. EVERY SITE THAT
// NAMES A SEAT FROM MEMORY (home_cpu, last_cpu, prev_cpu, A RANK ROW THE LOADER
// HAS NOT YET REWRITTEN AFTER A HOTPLUG) ASKS THIS FIRST.
static __always_inline bool seat_ok(s32 cpu)
{
	return (u32)cpu < nr_cpu_ids && cpu_up[cpu_slot((u32)cpu)];
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

// WHEN EACH CPU's RESIDENT LAST BEGAN TO RUN, STAMPED IN running() ON THAT CPU.
// A REMOTE READER GETS THE RESIDENT's SERVICE IN THIS RUN EXACTLY, WHERE ITS
// scx.slice MOVES ONLY AT THAT CPU's TICK OR NEXT SCHEDULING EVENT.
static u64 run_start_ns[MAX_CPUS];
// THE RESIDENT's RUN HABIT, avg_run_ns, STAMPED BESIDE IT. A REMOTE READER
// PRICES THE SEAT OFF THESE TWO AND NEVER DEREFERENCES THE RESIDENT's task_ctx.
static u64 run_expect_ns[MAX_CPUS];
// WHEN THE RESIDENT LAST WOKE, STAMPED BESIDE THEM: A RESIDENT THAT HAS NOT
// SLEPT FOR THE STARVATION BOUND IS ONE A FAN-OUT WAKE MAY TAKE FROM.
static u64 run_awake_ns[MAX_CPUS];
// WHEN A RESIDENT THAT HAD NOT SLEPT FOR THE STARVATION BOUND LAST BEGAN A RUN
// ON EACH CPU. SUCH A TASK TAKEN FROM WAITS ON ITS LANE AND IS BACK INSIDE A
// MILLISECOND, SO A STAMP YOUNGER THAN THE BOUND SAYS THE DOMAIN HOLDS ONE
// WHETHER OR NOT IT IS ON A CPU THIS INSTANT.
static u64 unslept_ran_ns[MAX_CPUS];

// THE SECOND LOOK. THE STEAL'S AGE BOUND SAYS HOW LONG A HEAD WAITS BEFORE IT
// MAY MOVE, AND A CPU ABOUT TO IDLE READ IT ONCE, AT THE INSTANT IT FREED: A
// HEAD A MICROSECOND OLD THERE WAS LEFT, THE CPU SLEPT, AND THE HEAD WAITED
// FOR ITS RESIDENT OR FOR THE NEXT CPU TO FREE (frame heavy, TRACED: 32 us
// MORE AT THE MEDIAN, STOLEN ANYWAY SEVEN TIMES IN TEN). A CPU THAT LEAVES A
// SEAT'S HEAD UNDER ITS AGE BOUND NOW LOOKS AGAIN UNTIL THE HEAD IS OLD ENOUGH
// TO TAKE OR GONE.
//   left_at  THE dispatch() WHOSE WALK LEFT SUCH A HEAD, BY ITS CLOCK READING
//   until    WHEN THE LAST HEAD THE FREEING LOOK LEFT COMES OF AGE
//   first    THE WALK NOW RUNNING IS THE FREEING LOOK'S
// ONLY THE LOOK OF A CPU A TASK JUST LEFT OPENS THE WINDOW AND NO LATER LOOK
// EXTENDS IT, SO A CPU BESIDE A SEAT THAT KEEPS FLOWING YOUNG HEADS SLEEPS WHEN
// THE WINDOW ENDS. THE WINDOW COUNTS THE PAIR-SPLIT HOLD NO DEARER THAN THE
// BASE COST: THE HOLD IS 3 TO 6.5 us WHERE SMT SETS THE SEAM, UNDER THE BASE
// COST, AND THE LOOK WAITS IT OUT (ENDED AT THE BASE COST ALONE THE LOOK GAVE
// UP A FEW MICROSECONDS SHORT OF MOST HEADS AND BOUGHT NOTHING); ON A PART
// WITHOUT SMT THE HOLD IS A THIRD OF A TARGET TO A WHOLE ONE, 103 TO 373 us AT
// 16 CPUs IN TWO L3s, AND NO CPU STAYS AWAKE FOR THAT. ONE CACHE LINE A CPU,
// WRITTEN BY THAT CPU ALONE. first IS HERE AND NOT IN THE WALK'S STATE:
// bpf_loop's CALLBACK IS VERIFIED TO CONVERGENCE OVER THAT STATE, AND IT MUST
// NOT GROW.
struct steal_look {
	u64 left_at;
	u64 until;
	bool first;
} __attribute__((aligned(64)));
static struct steal_look steal_look[MAX_CPUS];

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
// RE-DERIVED ON EVERY NEW TOPOLOGY VIA apply_tau_scaling().
// REFERENCE: CoDel, KATHLEEN NICHOLS AND VAN JACOBSON, "CONTROLLING QUEUE
// DELAY", ACM QUEUE 2012, AND RFC 8289 (NICHOLS, JACOBSON, McGREGOR,
// IYENGAR); THE TARGET'S MOTION IS A DAMPED HARMONIC OSCILLATOR.
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
static u64 codel_target_floor_ns;         // CORE-SCALED FLOOR FOR TARGET
static u64 codel_target_ns;               // THE LIVE TARGET, THE OSCILLATOR'S POSITION
static s64 oscillator_velocity_ns;        // DAMPED OSCILLATION VELOCITY
static u64 prev_rescue_snapshot;       // LAST-SEEN RESCUE COUNT
static u64 global_rescue_count;        // ATOMIC CROSS-CPU RESCUE ACCUMULATOR
static bool osc_reset_req;             // SET BY cpu_offline(), SERVED BY THE CPU-0
                                       // TICK: FORGET THE RESCUES COUNTED SO FAR
                                       // AND STOP THE VELOCITY

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

// THE UN-PARK, CALLED FROM THE CPU-0 TICK ALONE, WHEN ITS PARKED DETECTOR
// SEES A RESCUE, A MOVED EQUILIBRIUM OR THE HEARTBEAT. RE-PRIMES THE RESERVOIR
// ABOVE RELEASE SO A BURST CANNOT IMMEDIATELY RE-PARK, AND RESETS THE
// GRADED-BAND DIVIDER AND HEARTBEAT. DOES NOT TOUCH oscillator_velocity_ns OR
// codel_target_ns. EVERY PIECE OF OSCILLATOR AND ENVELOPE STATE HAS THE CPU-0
// TICK AS ITS ONE WRITER; THE REST OF THE PROGRAM ADDS TO global_rescue_count
// AND RAISES osc_reset_req.
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
static u64 codel_target_max_ns = 2000000ULL;

// TAU-SCALING: THE LAST topo.generation APPLIED. EVERY TICK COMPARES IT WITH
// THE LOADER'S; ON A NEW ONE ALL THE STATICS topo FEEDS ARE RE-DERIVED. ZERO
// MEANS THE LOADER HAS NOT WRITTEN YET AND THE FALLBACK CONSTANTS STAND.
static u64 last_topo_generation;

// R_eff-DERIVED CODEL EQUILIBRIUM TARGET. SET FROM topo.codel_eq_ns IN
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
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct panda_stats);
} stats_map SEC(".maps");

// THE FOUR TOPOLOGY TABLES AND THE TWO DOMAIN MAPS ARE DECLARED AT THEIR
// CEILINGS AND RESIZED BY THE LOADER BEFORE LOAD TO THE BOX'S CPU COUNT. A
// LOOKUP PAST THE RESIZED END RETURNS NULL, WHICH EVERY WALK TREATS AS THE
// SENTINEL.

// CACHE DOMAIN MAP: l2_domain[cpu] = group_id
// POPULATED BY RUST AT STARTUP FROM SYSFS TOPOLOGY
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MAX_CPUS);
	__type(key, u32);
	__type(value, u32);
} cache_domain SEC(".maps");

// EMERGENT DOMAIN MAP: cpu_domain[cpu] = DOMAIN ID FROM THE MIN-CONDUCTANCE
// TREE, PARTITIONED AT L3 GRANULARITY. THE SPILL STAYS INSIDE A DOMAIN AND THE
// SCATTER COUNTERS COUNT CROSSINGS OF ONE.
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


// PER-TASK CONTEXT

struct task_ctx {
	u64 last_woke_at;    // THE WAKE THIS RUN ENDS. ONE JOB, WAKE LATENCY: STAMPED
	                     // IN runnable(), READ AND CLEARED IN running().
	u64 cached_weight;
	u64 avg_run_ns;      // THE RUN HABIT: EWMA OF SERVICE PER RUN, NS. 0 = NEVER
	                     // RAN; SEEDED ON THE FIRST SAMPLE IN stopping().
	u64 wait_since;      // WHEN THIS QUEUE WAIT BEGAN; 0 = NOT WAITING. STAMPED ON
	                     // THE FIRST INSERT AFTER A RUN, PRESERVED ACROSS REQUEUES,
	                     // CLEARED IN running() AND quiescent(). THE SOJOURN BASE.
	u64 queued_on;       // DSQ ID + 1 OF THE QUEUE THIS TASK SITS ON, 0 = NONE.
	                     // SET ON INSERT, CLEARED BY ITS DEPARTURE.
	u64 run_exec_at;     // p->se.sum_exec_runtime AT running(). THE SERVICE LEDGER'S
	                     // BASE: stopping() DIFFS IT FOR TIME THE TASK ACTUALLY RAN,
	                     // WHICH IS ELAPSED MINUS THE IRQ TIME INSIDE THE WINDOW.
	u64 cut_at;          // WHEN THIS TASK WAS LAST SEATED BY A CUT; 0 = NO CUT
	                     // SINCE ITS LAST enqueue. STAMPED IN seat_task, READ AND
	                     // CLEARED AT enqueue's TOP. SEE CUT_SELF_KICK_NS.
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
	u64 awake_since;     // WHEN THIS TASK LAST WOKE. STAMPED IN runnable(), COPIED TO
			     // ITS SEAT IN running() FOR seat_spent().
	u32 wake_waker;      // PID + 1 OF THIS WAKE'S WAKER, 0 = NONE. STAMPED IN
	                     // select_cpu, WHERE THE WAKER IS current, FOR enqueue,
	                     // WHICH A QUEUED WAKEUP RUNS ON THE WAKEE'S CPU; CLEARED
	                     // IN running().
	s32 last_wakee_pid;  // PID THIS TASK MOST RECENTLY WOKE: THE WAKER'S SIDE OF
	                     // THE LEDGER. -1 = NONE YET.
	u32 same_wakee_runs; // CONSECUTIVE WAKES OF last_wakee_pid BY THIS TASK,
	                     // SATURATING. A 1:1 EXCHANGE CLIMBS IT; A PRODUCER
	                     // WAKING ITS WORKERS IN TURN RESETS IT EVERY WAKE.
	s32 last_cpu;        // LAST CPU THIS TASK RAN ON (FOR CACHE AFFINITY)
	u32 handoff_seat;    // DSQ ID + 1 OF A DIRECT HAND-OFF'S SEAT, WHOSE CLOCK running()
	                     // WRITES ON THAT CPU; 0 = NONE. SEE seat_handoff_fast.
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
};

struct {
	__uint(type, BPF_MAP_TYPE_TASK_STORAGE);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__type(key, int);
	__type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

// HELPERS

// THE DOMAIN OF A CPU: THE EMERGENT DOMAIN FROM THE MIN-CONDUCTANCE
// TREE IN cpu_domain, NOT A DISCRETE llc_domain. THE PARTITION TARGETS L3
// GRANULARITY, SO ON A REAL PART THE TWO AGREE AND THE BOUNDARY IS DRAWN BY THE
// CONDUCTANCE LANDSCAPE RATHER THAN A HARDCODED TABLE.
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
	if (!tctx || !tctx->queued_on)
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

static __always_inline struct panda_stats *get_stats(void);
static __always_inline u64 sweep_band_ns(void);

// A SEAT'S WAIT: ITS QUEUE'S WAIT PLUS WHAT THE RESIDENT HAS LEFT. queue_wait
// SEES QUEUED WORK ONLY, SO A CPU RUNNING ONE TASK WITH AN EMPTY QUEUE READ AS
// FREE TO EVERY SEAT DECISION. p->scx.slice IS THE RESIDENT'S GRANTED TIME
// REMAINING, COUNTED DOWN BY THE KERNEL AT EACH ACCOUNTING POINT: A MEASURED
// UPPER BOUND, NEVER A PREDICTION. A RESIDENT THAT BLOCKS EARLY FREES THE SEAT
// SOONER, SO THE ERROR RUNS TOWARD MOVING AND NEVER TOWARD STRANDING.
// THE RESIDENT'S RUN HABIT SHARPENS THE BOUND: run_expect_ns IS ITS avg_run_ns
// AND run_start_ns WHEN IT TOOK THE CPU, BOTH STAMPED BY running() ON THAT CPU.
// WHILE IT RUNS INSIDE ITS HABIT, WHAT IT HAS LEFT OF THAT HABIT IS TAKEN WHEN
// SHORTER THAN THE GRANT, SO A SEAT WHOSE RESIDENT IS A 240us JOB WORKER READS
// AS FREEING IN MICROSECONDS WHERE THE GRANT ALONE READ A FULL SLICE. A
// RESIDENT PAST ITS HABIT IS NOT BEHAVING LIKE ITS HISTORY, SO THE GRANT
// STANDS. nr_seat_expect_used AND nr_seat_expect_overrun COUNT THE TWO.
// NOTHING IS ADDED FOR THE IDLE TASK, FOR A RESIDENT OUTSIDE sched_ext (ITS
// slice IS STALE), OR FOR self, THE TASK BEING SEATED, WHICH IS STILL CURRENT
// WHEN ITS OWN REQUEUE IS PLACED. THE BAND CAPS THE TERM, SO AN UNBOUNDED
// SLICE CANNOT OVERFLOW THE SUM.
static __always_inline u64 seat_wait(s32 cpu, const struct task_struct *self,
				     u64 now)
{
	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return 0;
	u32 slot = cpu_slot((u32)cpu);
	u64 wait = queue_wait(&pcpu_qclock[slot], now);
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!curr || curr == self)
		return wait;
	// THE RESIDENT IS READ THROUGH ITS POINTER. scx_bpf_cpu_curr() HANDS
	// BACK AN RCU-PROTECTED task_struct THE VERIFIER LETS A PROGRAM LOAD
	// FROM, EACH FIELD ONE FAULTING LOAD IN THE JIT. BPF_CORE_READ MADE EACH
	// OF THE THREE A bpf_probe_read_kernel HELPER CALL: 24 CALL SITES IN
	// select_cpu AND 9 IN enqueue, THREE ON EVERY BUSY SEAT PRICED. THE SAME
	// THREE FIELDS ARE READ, SO THE PRICE IS UNCHANGED.
	if ((curr->flags & PF_IDLE) ||
	    !(curr->scx.flags & SCX_TASK_QUEUED))
		return wait;
	u64 left = curr->scx.slice;
	u64 expect = run_expect_ns[slot];
	if (expect) {
		u64 start = run_start_ns[slot];
		u64 ran = now > start ? now - start : 0;
		struct panda_stats *s = get_stats();
		if (ran < expect) {
			u64 rem = expect - ran;
			if (rem < left)
				left = rem;
			if (s)
				s->nr_seat_expect_used += 1;
		} else if (s) {
			s->nr_seat_expect_overrun += 1;
		}
	}
	// THE BAND BOUNDS ANY WAITER'S TIME BEHIND A RESIDENT, SO THE RESIDENT
	// TERM NEVER EXCEEDS IT. A HOG'S EMPTY SEAT PRICES AT ONE BAND, NOT FOUR
	// TARGETS, AND A FAN-OUT WAKE MAY TAKE IT INSTEAD OF STACKING BEHIND OTHER
	// JOBS ON A WORKER'S SEAT. THE CAP AT THE LIVE TARGET ALONE WAS MEASURED
	// AND LOST THE DEEP TAIL; AT THE FLOOR IT HOLDS IT.
	{
		u64 cap = sweep_band_ns();
		if (left > cap)
			left = cap;
	}
	return wait + left;
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
static __always_inline void cross_domain_bump(struct panda_stats *s, u32 idx,
				      s32 last_home, s32 dst)
{
	if (!s || idx >= XDOM_PATHS || last_home < 0)
		return;
	if (cpu_domain_of(last_home) != cpu_domain_of(dst))
		s->nr_cross_domain[idx] += 1;
}

static __always_inline struct panda_stats *get_stats(void)
{
	u32 zero = 0;
	return bpf_map_lookup_elem(&stats_map, &zero);
}

// THE KNOB SET IS ONE STATIC, DERIVED IN apply_tau_scaling(). THE POINTER IS
// NEVER NULL; CALLERS' NULL TESTS ARE THE LIFTED SHAPE AND COST A COMPARE.
static __always_inline struct tuning_knobs *get_knobs(void)
{
	return &knobs_g;
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

static __always_inline void count_l2_affinity(struct panda_stats *s,
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
// BUDGET. THE CPU IT RETURNS IS CLAIMED: ITS IDLE BIT IS CLEAR, SO THE CALLER
// MUST SEAT THERE.
// src_allowed: THE CALLER ALREADY TESTED src_cpu AGAINST allowed AND IT
// PASSED, SO THE ANCHOR'S MASK TEST IS NOT ASKED A SECOND TIME.
static __always_inline s32 find_idle_by_affinity(s32 src_cpu,
						 const struct cpumask *allowed,
						 bool src_allowed)
{
	if (src_cpu < 0 || (u32)src_cpu >= nr_cpu_ids)
		return -1;

	// THE ANCHOR IS THE FIRST CANDIDATE AND IS TESTED EXPLICITLY. affinity_rank
	// IS BUILT WITH `c != cpu` IN topology.rs build_affinity_rank, SO src_cpu IS
	// NOT IN ITS OWN RANK AND THE WALK BELOW CANNOT RETURN IT. SLOT 0 IS THE SMT
	// SIBLING, NOT SELF.
	// AN IDLE PEER CANNOT START THE TASK SOONER THAN AN IDLE ANCHOR AND COSTS AN
	// L2 RELOAD OF ~4,500 LLC REFERENCES, SO THE ANCHOR WINS WHEN BOTH ARE IDLE.
	if (seat_ok(src_cpu) &&
	    (src_allowed || !allowed || bpf_cpumask_test_cpu(src_cpu, allowed)) &&
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
		// OFFLINE CPU -> SKIP WITHOUT COSTING BUDGET. THE LOADER'S ROWS HOLD
		// ONLINE CPUs ONLY, BUT IT REWRITES THEM UP TO A SECOND AFTER A
		// HOTPLUG, AND UNTIL THEN A ROW STILL LISTS THE CPU THAT WENT DOWN.
		if (!seat_ok((s32)*val))
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
// THE SCHEDULER. SUCH A WAKE IS REFUSED HERE AND TAKES THE QUEUE INSTEAD, AND
// SO IS ONE WHOSE SEAT IS OFFLINE: THE KERNEL BOUNCES THAT INSERT TO ITS
// GLOBAL DSQ.
static __always_inline bool seat_cut(struct task_struct *p, s32 seat, u64 sl,
				     u64 enq_flags)
{
	if (!seat_ok(seat))
		return false;
	if (seat != scx_bpf_task_cpu(p) &&
	    (is_migration_disabled(p) ||
	     !bpf_cpumask_test_cpu(seat, p->cpus_ptr)))
		return false;
	// THE CUT INSERTS WITH THE CALLER'S FLAGS ALONE; THE KICK BELOW CARRIES
	// THE PREEMPT. WITH SCX_ENQ_HEAD | SCX_ENQ_PREEMPT ON THIS INSERT THE
	// prism-scale LATENCY PROBE's p99 READ 1,511 us AND DEADLINE MISSES 22
	// PERCENT AT 12C; WITH THEM OFF, 70 us AND 1.5 PERCENT, PANDEMONIUM's
	// BAND. THE A/B IS ON THE LEDGER.
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)seat, sl, enq_flags);
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
static __always_inline s32 phi_warm_target(s32 anchor,
					   const struct cpumask *allowed,
					   bool anchor_allowed)
{
	return find_idle_by_affinity(anchor, allowed, anchor_allowed);
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
// WHOSE LAST WAKES WENT TO OTHERS, IS A FAN-OUT AND WAITS ON ITS SEAT. A FORK
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
// THE CLOCK MOVES. THE JUDGE OF THE QUEUE IT JOINS PACES IT, THE TARGET'S LANE
// FOR A PLAIN REQUEUE (lane) AND ITS SEAT FOR A PARTNER'S: AN OWED REQUEUE
// PREEMPTS AT MOST ONCE PER QUEUE PER TARGET, SHARED WITH EVERY OTHER PREEMPT
// THAT JUDGE PACES. PACED ON THE SEAT'S JUDGE, A REQUEUE BOUND FOR THE LANE
// SPENT THE SEAT'S PACE ON A QUEUE IT NEVER JOINED.
// A CLAIM UNDER THE BOUND ASKS THE JUDGE NOTHING. queue_act() RESETS ITS ACT
// COUNT WHEN THE WAIT IT IS SHOWN IS UNDER THE BOUND, WHICH IS RIGHT FOR A
// QUEUE'S OWN WAIT AND WRONG FOR ONE TASK'S: A HOG REQUEUES EVERY SLICE WITH
// A CLAIM OF ZERO, AND EACH ONE RESET THE COUNT THE SWEEP HAD BUILT ON THAT
// CPU'S SEAT, SO ITS PACE THERE NEVER PASSED THE FIRST ACT. ONLY THE QUEUE'S
// OWN WAIT, READ BY THE SWEEP AND THE TICK, RESETS A JUDGE NOW.
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
					     s32 target, bool is_wakeup,
					     bool lane)
{
	if (target < 0 || (u64)target >= nr_cpu_ids)
		return SCX_KICK_IDLE;
	// NO RESIDENT TEST. scx_bpf_cpu_curr() IS NEVER NULL FOR A CPU INSIDE
	// nr_cpu_ids -- AN IDLE SEAT'S curr IS ITS IDLE TASK -- SO THE NULL TEST
	// THAT STOOD HERE NEVER RETURNED, AND EVERY PRICED SEAT PAID A KFUNC AND
	// THE SEAT'S rq LINE FOR IT. TIER 2's ENTRY TEST WAS THE SAME CALL.
	if (is_wakeup)
		return wake_cuts(tctx) ? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
	u32 rbase = (u32)target * MAX_AFFINITY_CANDIDATES;
	u32 *rdx = bpf_map_lookup_elem(&reff_value, &rbase);
	u32 rd = rdx ? *rdx : 0;
	u64 near_extra = (rd == (u32)-1) ? 0 : (u64)rd;
	u64 rnow = bpf_ktime_get_ns();
	u64 claimed = (tctx && tctx->wait_since && rnow > tctx->wait_since)
		    ? rnow - tctx->wait_since : 0;
	u64 owed = codel_target_ns + near_extra;
	if (claimed >= owed &&
	    queue_act(lane ? &lane_qclock[cpu_slot((u32)target)]
			   : &pcpu_qclock[cpu_slot((u32)target)],
		      claimed, owed, codel_target_ns, rnow))
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

// A CUT'S OWN KICK, MET. seat_cut INSERTS THE WAKEE ON THE SEAT'S LOCAL DSQ
// AND SENDS THE SEAT A PREEMPT KICK, AND THE KICK DOES NOT KNOW WHOM IT WAS
// FOR: WHEN THE SEAT'S RESIDENT BLOCKS BEFORE THE KICK LANDS, THE WAKEE IS
// ALREADY RUNNING WHEN IT DOES, AND THE KICK ZEROES THE WAKEE'S SLICE. IT
// REQUEUES TO ITS LANE, BEHIND WHATEVER TOOK THE CPU, FOR ABOUT A TICK. SO THE
// CUT IS STAMPED TWICE: ON THE TASK, WHEN; ON THE SEAT, FOR WHOM. A REQUEUE
// INSIDE THIS WINDOW OF ITS OWN CUT, ON THE SEAT WHOSE LATEST CUT WAS FOR IT,
// WAS PREEMPTED BY THAT CUT'S KICK AND GOES BACK TO THE HEAD OF ITS CPU'S LOCAL
// DSQ, WITH NO KICK. THE SEAT'S STAMP IS WHAT KEEPS A SECOND CUT HONEST: THE
// FIRST CUTTER, PREEMPTED BY A LATER CUT ONTO THE SAME SEAT, IS NO LONGER THE
// PID THE SEAT NAMES AND REQUEUES AS ANY RESIDENT DOES.
#define CUT_SELF_KICK_NS 50000ULL

// THE SEAT. EVERY PLACE A TASK IS PUT ON A CPU'S SEAT DOES THE SAME FOUR
// THINGS IN THIS ORDER: HAND IT OFF IF THE SEAT IS THE CLAIMED IDLE CPU WITH
// AN EMPTY QUEUE (seat_direct); CUT IF THE WAKE MAY AND THE SEAT IS ITS OWN
// PER-CPU QUEUE (seat_cut); ELSE INSERT IT ON dsq IN DEADLINE ORDER; RECORD
// THE ARRIVAL ON THAT QUEUE'S CLOCK; AND, ONLY WHEN IT WAS QUEUED, ISSUE THE
// CALLER'S PRICED KICK. THE CALLER DECIDES THE SEAT, THE QUEUE, WHETHER THE
// WAKE MAY CUT AND WHAT THE KICK IS. THE SEVEN SEATS IN select_cpu AND enqueue
// ARE THIS ONE SHAPE.
enum seat_how { SEAT_QUEUED = 0, SEAT_HANDOFF = 1, SEAT_CUT = 2 };

static __always_inline enum seat_how seat_task(struct task_struct *p,
					       struct task_ctx *tctx, s32 seat,
					       s32 claimed, u64 dsq, u64 sl,
					       u64 dl, bool may_cut, u64 kick,
					       u64 enq_flags, u64 now)
{
	enum seat_how how = SEAT_QUEUED;
	if (seat_direct(p, seat, claimed, sl, enq_flags))
		how = SEAT_HANDOFF;
	else if (may_cut && dsq == (u64)seat &&
		 seat_cut(p, seat, sl, enq_flags)) {
		how = SEAT_CUT;
		pcpu_qclock[cpu_slot((u32)seat)].cut_pid = p->pid;
		if (tctx)
			tctx->cut_at = now;
	} else
		scx_bpf_dsq_insert_vtime(p, dsq, sl, dl, enq_flags);
	// how IS MADE OPAQUE HERE SO CLANG DOES NOT THREAD THE KICK TEST BACK INTO
	// THE THREE ARMS ABOVE AND COPY THE ARRIVAL INTO EACH. THE CLOCK READ THAT
	// STOOD HERE KEPT THEM APART; WITHOUT IT THE COPIES ADDED 8 TO
	// select_cpu's CYCLOMATIC COUNT AND 4 TO enqueue's ON montauk's STATIC LANE.
	asm volatile("" : "+r"(how));
	// THE ARRIVAL TAKES THE CALLER'S CLOCK WHERE A FRESH READ AFTER THE INSERT
	// STOOD. EVERY CALLER READS IT AFTER ITS PICK, SO THE STAMP MOVES ONLY BY
	// THE STRAIGHT-LINE WORK FROM THERE TO THE INSERT: THE KICK PRICE, THE
	// HAND-OFF TEST AND THE INSERT ITSELF. A READ TAKEN BEFORE A PICK WOULD
	// MOVE IT BY THE SPILL WALK, ON EXACTLY THE LOADED SEATS WHOSE CLOCKS
	// THE STEAL AND THE SWEEP READ.
	qclock_arrive(tctx, dsq, now);
	if (how == SEAT_QUEUED && kick != KICK_NONE)
		scx_bpf_kick_cpu(seat, kick);
	return how;
}

// THE COMMON WAKE, SEATED LEAN. THE WALK CLAIMED AN IDLE target; WHEN ITS
// PER-CPU QUEUE IS EMPTY THE FULL PICK RETURNS IT (AN EMPTY QUEUE BEHIND AN
// IDLE RESIDENT WAITS ZERO) AND seat_direct HANDS IT OFF, SO THE SEAT PRICE,
// THE SPILL SEARCH AND TWO OF THE THREE CLOCK READS DECIDE NOTHING AND ARE
// LEFT OUT. WHAT THE FULL PATH WOULD HAVE WRITTEN IS WRITTEN HERE: THE
// PARTNER'S WARM STAMP, THE WAIT BASE, THE SEAT'S CLOCK. MEASURED FROM THE
// WAKER'S SIDE: THE FRAME'S TEN-WAKE FUTEX CALL READ 47.7 us AGAINST EEVDF'S
// 13.4 WITH EVERY WAKE PAYING THE FULL PATH, 4.9 us A WAKE AGAINST 1.65, OF
// WHICH select_cpu WAS 1.4. A QUEUE THAT IS NOT EMPTY TAKES THE FULL PATH.
static __always_inline u64 task_slice(const struct task_ctx *tctx,
				      const struct tuning_knobs *knobs);

static __always_inline bool seat_handoff_fast(struct task_struct *p,
					      struct task_ctx *tctx, s32 target,
					      const struct tuning_knobs *knobs)
{
	if ((u64)target >= nr_cpu_ids || scx_bpf_dsq_nr_queued((u64)target))
		return false;
	u64 now = bpf_ktime_get_ns();
	u64 sl = 1000000;
	if (tctx) {
		if (is_handoff_partner(tctx) && (u32)target < MAX_CPUS)
			pair_warm_ns[cpu_slot((u32)target)] = now;
		if (!tctx->wait_since)
			tctx->wait_since = now;
		sl = task_slice(tctx, knobs);
	}
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | (u64)target, sl, 0);
	// THE SEAT RECORDS ITS OWN HAND-OFF. qclock_arrive HERE WAS AN ATOMIC ON
	// THE SEAT'S CLOCK, ANOTHER CPU'S CACHE LINE, WHICH THAT CPU'S running()
	// THEN WROTE BACK: TWO LINE TRANSFERS A WAKE, AND montauk's LINE PROFILER
	// PUT 44 PERCENT OF select_cpu's OWN CYCLES ON THAT ARRIVAL. A HAND-OFF'S
	// ARRIVAL AND DEPARTURE CANCEL IN THE COUNTS, SO running() WRITES WHAT THE
	// DEPARTURE WOULD HAVE, THE PROGRESS AND THE SOJOURN, ON ITS OWN LINE. THE
	// SEAT READS NO WAIT FOR THE MICROSECONDS BETWEEN THE WAKE AND THE RUN
	// INSTEAD OF THOSE MICROSECONDS, BELOW EVERY BOUND THE PROGRAM COMPARES.
	if (tctx) {
		qclock_depart(tctx, now, false);
		tctx->handoff_seat = (u32)target + 1;
	}
	return true;
}

// WHAT WAKING AN IDLE CPU COSTS A WAKEE, AGAINST WHICH A BUSY WAKER'S SEAT IS
// PRICED ON THE TIGHT PATH: 2 us, THE SIMULATION THREAD'S MEDIAN WAKE-TO-RUN
// ON AN IDLE SEAT AT THE FRAME'S JOIN ON THIS BOX (2.06 us), WITH EEVDF'S
// 1.44 ON THE SAME SEAT BESIDE IT.
#define WAKER_CORE_WAKE_NS 2000ULL

static __always_inline s32 warm_seat_pick(struct task_struct *p,
					    struct task_ctx *tctx,
					    struct tuning_knobs *knobs,
					    bool is_wakeup)
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
	// THE CLOCK IS READ PAST THE THREE REFUSALS ABOVE, WHICH NEED NONE: A
	// FORK OR AN EXEC THAT IS NO PARTNER, AND EVERY PLAIN REQUEUE PAST TIER 1,
	// LEAVES BEFORE IT.
	u64 now = bpf_ktime_get_ns();
	// A WAKEUP AND A REQUEUE WANT DIFFERENT ANCHORS.
	// A WAKEUP HAS NO SEAT AND IS BEING PLACED REGARDLESS, SO IT ANCHORS ON THE
	// PINNED home_cpu -- A PULL TOWARD A FIXED POINT IS SELF-LIMITING, BECAUSE
	// ONCE THE TASK IS HOME NO FURTHER PULL FIRES. last_cpu IS REWRITTEN EVERY
	// stopping() AND HAS NO RESTORING FORCE AT ALL.
	// A REQUEUE ALREADY HAS A SEAT. IT WAS PASSED OVER, NOT DISPLACED, SO SENDING
	// IT TO WHICHEVER CPU IT FIRST RAN ON IS PURE ADDED MOVEMENT. IT ANCHORS ON
	// last_cpu.
	// EITHER ARM FALLS BACK TO THE OTHER FIELD WHEN ITS OWN IS UNSET OR
	// NAMES A CPU THAT HAS GONE OFFLINE.
	s32 lc = is_wakeup ? tctx->home_cpu : tctx->last_cpu;
	if (!seat_ok(lc))
		lc = is_wakeup ? tctx->last_cpu : tctx->home_cpu;
	if (!seat_ok(lc))
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
// AND KEEPS THE INLINED select_cpu UNDER THE INSTRUCTION BUDGET. THE STEAL-SIDE
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
// do-not-re-attempt). THE BOUND IS THE DOMAIN PARTITION, SO A
// SPILL NEVER CROSSES AN L3. A FOREIGN PEER IS SKIPPED WITHOUT COSTING BUDGET.
static __always_inline s32 find_spill_seat(s32 src_cpu,
					     const struct cpumask *allowed,
					     u64 now)
{
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
		if (!seat_ok((s32)peer))
			continue;
		if (allowed && !bpf_cpumask_test_cpu((s32)peer, allowed))
			continue;
		if (cpu_domain_of((s32)peer) != src_dom)
			continue;

		u64 cost = seat_wait((s32)peer, NULL, now) + phi_base_cost_ns;
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

// A SEAT A FAN-OUT WAKE MAY TAKE: ITS RESIDENT HAS HAD ITS FIRST TARGET, WHICH
// THE CLOCK PROMISES ANY TASK BEFORE IT IS JUDGED (resident_owed), AND NOTHING
// WAITS ON ITS PER-CPU DSQ OR ITS LOCAL DSQ. THE RESIDENT IS A sched_ext TASK
// THAT IS NEITHER THE TASK BEING SEATED NOR ITS WAKER.
// TWO KINDS, BY THE RESIDENT'S OWN HISTORY AND NOT A CLASS. ONE THAT HAS NOT
// SLEPT FOR THE STARVATION BOUND, lag_cap_ns, STAYS RUNNABLE WHATEVER IS
// TAKEN FROM IT: SEAT_UNSLEPT. ONE THAT BLOCKS OF ITS OWN ACCORD, A FRAME'S
// RENDER STAGE 1.8 ms LONG, IS SEAT_SPENT, AND THE WALK TAKES FROM IT ONLY
// WHERE NO RESIDENT OF THE DOMAIN IS UNSLEPT: BESIDE RESIDENTS THAT NEVER
// YIELD, A TASK CUT MID-STAGE WAITS ON ITS LANE FOR A CPU THAT DOES NOT COME
// FREE. *unslept IS SET FOR SUCH A RESIDENT WHETHER OR NOT ITS SEAT MAY BE
// TAKEN NOW, AND FOR A SEAT ONE RAN ON INSIDE THE LAST BOUND: TAKEN FROM, IT
// IS ON A LANE AND NOT ON ANY CPU.
// MEASURED ON FRAME AT EIGHT ROUNDS. TAKING FROM ANY SPENT RESIDENT, CONTENDED'S
// 1% LOW READ 315 WHERE THIS READS 336, RENDER SENT TO ITS LANE THREE TIMES AS
// OFTEN. TAKING FROM THE UNSLEPT ALONE, HEAVY READ 420 FPS WHERE THIS READS 424.
// ASKING ONLY WHO IS ON A CPU THIS INSTANT LOSES THE UNSLEPT MID-BURST, EACH
// JUST TAKEN FROM, AND CONTENDED'S 1% LOW READ 319.
enum seat_take { SEAT_KEPT = 0, SEAT_SPENT = 1, SEAT_UNSLEPT = 2 };

static __always_inline enum seat_take seat_spent(s32 cpu,
						 const struct task_struct *p,
						 u32 waker_pid, u64 now,
						 bool *unslept)
{
	if (!seat_ok(cpu) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
		return SEAT_KEPT;
	u32 slot = cpu_slot((u32)cpu);
	u64 ran = unslept_ran_ns[slot];
	if (ran && ran <= now && now - ran < lag_cap_ns)
		*unslept = true;
	struct task_struct *curr = __COMPAT_scx_bpf_cpu_curr(cpu);
	if (!curr || curr == p || (curr->flags & PF_IDLE) ||
	    !(curr->scx.flags & SCX_TASK_QUEUED))
		return SEAT_KEPT;
	u64 awake = run_awake_ns[slot];
	bool never = awake && awake <= now && now - awake >= lag_cap_ns;
	if (never)
		*unslept = true;
	if ((u32)curr->pid == waker_pid)
		return SEAT_KEPT;
	u64 start = run_start_ns[slot];
	if (start > now || now - start < codel_target_ns)
		return SEAT_KEPT;
	if (scx_bpf_dsq_nr_queued((u64)cpu) ||
	    scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | (u64)cpu))
		return SEAT_KEPT;
	return never ? SEAT_UNSLEPT : SEAT_SPENT;
}

// THE SEAT TO TAKE IN near'S CACHE DOMAIN: near ITSELF, THEN ITS PEERS IN
// R_eff ORDER UNDER THE SPILL'S BUDGET. THE NEAREST UNSLEPT RESIDENT'S; WHERE
// THE DOMAIN HOLDS NONE AT ALL, THE NEAREST SPENT ONE'S; ELSE -1.
static __always_inline s32 spent_seat(const struct task_struct *p, s32 near,
				      u32 waker_pid, u64 now)
{
	if (near < 0 || (u32)near >= nr_cpu_ids)
		return -1;
	bool unslept = false;
	s32 sleeper = -1;
	enum seat_take k = seat_spent(near, p, waker_pid, now, &unslept);
	if (k == SEAT_UNSLEPT)
		return near;
	if (k == SEAT_SPENT)
		sleeper = near;
	u32 base = (u32)near * MAX_AFFINITY_CANDIDATES;
	u32 dom = cpu_domain_of(near);
	u32 checked = 0;
	int i;
	bpf_for(i, 0, PCPU_SPILL_SCAN_MAX) {
		u32 key = base + (u32)i;
		u32 *val = bpf_map_lookup_elem(&affinity_rank, &key);
		if (!val || *val == (u32)-1)
			break;
		s32 peer = (s32)*val;
		if (cpu_domain_of(peer) != dom)
			continue;
		k = seat_spent(peer, p, waker_pid, now, &unslept);
		if (k == SEAT_UNSLEPT)
			return peer;
		if (k == SEAT_SPENT && sleeper < 0)
			sleeper = peer;
		if (++checked >= pcpu_spill_search_budget)
			break;
	}
	return unslept ? -1 : sleeper;
}

// A CPU THE TASK MAY RUN ON: near WHEN IT IS ONLINE AND THE TASK'S MASK ALLOWS
// IT, ELSE ONE PICKED FROM THE MASK ON near's NODE, AN IDLE ONE FIRST. A USER
// DSQ ADMITS ANY TASK, BUT ONLY A CPU THE TASK MAY RUN ON CAN MOVE IT TO LOCAL,
// SO A TASK QUEUED ON A CPU OUTSIDE ITS MASK WAITS FOR A STEAL THAT NEED NOT
// COME. THE KERNEL'S PICK DRAWS FROM THE MASK, WHICH KEEPS ITS OFFLINE CPUs, SO
// A PICK THAT IS OFFLINE, AND AN EMPTY MASK, WHICH A RUNNABLE TASK CANNOT HAVE,
// FALL BACK TO THE TASK'S OWN CPU.
static __always_inline s32 allowed_seat(const struct task_struct *p, s32 near)
{
	if (seat_ok(near) && bpf_cpumask_test_cpu(near, p->cpus_ptr))
		return near;
	s32 node = (u64)near < nr_cpu_ids ? __COMPAT_scx_bpf_cpu_node(near) : 0;
	if (node < 0 || (u32)node >= nr_nodes)
		node = 0;
	s32 cpu = __COMPAT_scx_bpf_pick_any_cpu_node(p->cpus_ptr, node, 0);
	return seat_ok(cpu) ? cpu : scx_bpf_task_cpu(p);
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
//      MID-FLIGHT) OR OFFLINE SEATS ON AN ONLINE CPU OF THE MASK INSTEAD
//      (allowed_seat), SO NOTHING WAITS ON A QUEUE ITS TASK MAY NOT LEAVE
//      FROM OR NO CPU SERVES.
// *out_cpu RECEIVES THE CPU SCX SHOULD WAKE, THE PER-CPU DSQ OWNER WE LANDED IN.
// now IS THE CALLER'S CLOCK. THE TIGHT SEAT AND select_cpu's WARM SEAT PASS
// THE READ THAT STAMPED THE WAIT BASE ONE STORE EARLIER; THE OTHER CALLERS
// READ IT AT THE CALL.
static __always_inline u64 pick_pcpu_dsq_with_spill(const struct task_struct *p,
						    s32 src_cpu,
						    const struct cpumask *allowed,
						    bool keep_own,
						    bool resident_leaving,
						    u64 now,
						    s32 *out_cpu)
{
	bool src_ok = seat_ok(src_cpu) &&
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
	s32 spill = hold_own ? -1 : find_spill_seat(src_cpu, allowed, now);
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
//   (tau, k_i) PAIR. WORST CASE: tau=40e6 (TAU_CEIL_NS) * K_BATCH_CAP_Q16
//   (98304) = 3.9e12, COMFORTABLY INSIDE u64 (max ~1.8e19).
static __always_inline u64 scale_tau(u64 tau_ns, u64 k_q16)
{
	return (tau_ns * k_q16) >> K_Q16_SHIFT;
}

// TAU-SCALING RE-DERIVATION.
//   THE LOADER WRITES topo BEFORE IT ATTACHES AND AGAIN ON HOTPLUG, ITS
//   GENERATION LAST. init() AND EVERY TICK CALL THIS; ON A GENERATION NOT YET
//   APPLIED, EVERY STATIC topo FEEDS IS RE-DERIVED VIA scale_tau() AND CLAMPED
//   TO ITS SAFETY RAIL. THE KEY IS THE GENERATION AND NOT tau: A HOTPLUG THAT
//   LEAVES tau WHERE IT WAS STILL MOVES codel_eq_ns AND THE PEER COUNT.
static __always_inline void apply_tau_scaling(void)
{
	// THE GENERATION IS READ BEFORE THE FIELDS AND THE LOADER WRITES IT AFTER
	// THEM, SO A GENERATION SEEN HERE HAS ITS FIELDS BEHIND IT. FIELDS CAUGHT
	// MID-WRITE BELONG TO A GENERATION NOT YET PUBLISHED, AND THE TICK AFTER IT
	// IS PUBLISHED DERIVES AGAIN. THE CAS LETS ONE CPU DERIVE A GENERATION AND
	// THE REST RETURN ON ONE COMPARE.
	u64 generation = topo.generation;
	u64 snap = __sync_fetch_and_add(&last_topo_generation, 0);
	if (generation == snap)
		return;
	u64 tau_ns = topo.tau_ns;
	u64 codel_eq_ns = topo.codel_eq_ns;
	if (tau_ns == 0)
		return;
	if (!__sync_bool_compare_and_swap(&last_topo_generation, snap, generation))
		return;

	// DERIVE EACH TIMING CONSTANT VIA k_i * tau, THEN CLAMP AS A
	// SAFETY RAIL (KILL SWITCH IF A k_i IS MISCALIBRATED).
	u64 v;

	v = scale_tau(tau_ns, K_CODEL_FLOOR);
	if (v < CODEL_FLOOR_MIN_NS) v = CODEL_FLOOR_MIN_NS;
	if (v > 800000ULL) v = 800000ULL;
	codel_target_floor_ns = v;

	// THE BASE COST, TAU-DERIVED LIKE EVERY OTHER BOUND IN THE GATE.
	v = scale_tau(tau_ns, K_PHI_BASE_Q16);
	if (v < PHI_BASE_MIN_NS) v = PHI_BASE_MIN_NS;
	if (v > PHI_BASE_MAX_NS) v = PHI_BASE_MAX_NS;
	phi_base_cost_ns = v;

	v = scale_tau(tau_ns, K_CODEL_MAX);
	// NO FIXED FLOOR: A FIXED 1ms FLOOR PINS codel_target_max AT 12C
	// (0.05*13.3ms = 665us -> 1ms) AND 8C, OVERRIDING THE tau-DERIVED VALUE.
	// THE CEILING IS FLOORED INSTEAD AT THE OSCILLATOR'S OWN FLOOR TIMES THE
	// WINDOW'S RATIO, K_CODEL_MAX OVER K_CODEL_FLOOR, SO THE WINDOW KEEPS ITS
	// SHAPE WHERE THE FLOOR'S RAIL BINDS. tau FALLS AS ABOUT 160ms OVER THE CPU
	// COUNT ON A SYMMETRIC MULTI-L3 PART: AT 64 THREADS IN EIGHT L3s IT IS
	// 2.5ms, THE FLOOR IS ITS 200us RAIL AND 0.05 tau IS 125us. LIFTED ONLY TO
	// THE FLOOR, THE CEILING, THE FLOOR AND THE EQUILIBRIUM WERE ONE NUMBER
	// THERE AND THE OSCILLATOR COULD NOT MOVE; AT 16 CPUs IN TWO L3s THE WINDOW
	// WAS 200 TO 500us WITH THE EQUILIBRIUM CLAMPED ONTO ITS FLOOR. WHERE THE
	// RAIL DOES NOT BIND THE RATIO OF THE FLOOR IS 0.05 tau TO THE ROUNDING AND
	// NEVER ABOVE IT, SO NOTHING MOVES: 233 TO 667us AT 12C.
	{
		u64 shaped = codel_target_floor_ns * K_CODEL_MAX / K_CODEL_FLOOR;
		if (v < shaped) v = shaped;
	}
	if (v > 8000000ULL) v = 8000000ULL;           // CEILING 8MS (stall-blind guard)
	codel_target_max_ns = v;

	// SPECTRAL-GAP CODEL EQUILIBRIUM. THE LOADER SETS IT AS A POSITION INSIDE
	// THIS WINDOW, THE FLOOR'S RAIL INCLUDED (topology.rs codel_window), SO THE
	// TWO CLAMPS BELOW ARE A GUARD AND NOT THE SOURCE OF THE VALUE. ZERO MEANS
	// THE LOADER HAS NOT YET WRITTEN -- KEEP THE FALLBACK.
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
		u32 lo = topo.affinity_domain_peers < 3 ? topo.affinity_domain_peers : 3;
		if (lo < 1) lo = 1;
		if (b < lo) b = lo;
		if (b > ceil) b = ceil;
		affinity_search_online = b;
	}

	// STARVATION BOUND, AND seat_spent's TEST OF A RESIDENT THAT DOES NOT SLEEP:
	// lag_cap_ns = K_LAG_CAP * tau
	// (1.0 * tau, 13.3MS AT THE 12C REFERENCE), CLAMPED [8MS, 80MS].
	v = scale_tau(tau_ns, K_LAG_CAP);
	if (v < 8000000ULL)  v = 8000000ULL;
	if (v > 80000000ULL) v = 80000000ULL;
	lag_cap_ns = v;

	// THE WINDOWS: AS MANY AS KEEP A SEAT OUT OF ALL OF THEM NO LONGER THAN
	// lag_cap_ns, AND THE SEATS FROM ONE WINDOW'S START TO THE NEXT'S. SEE
	// sweep_win_count.
	{
		u32 n = nr_cpu_ids;
		u32 gap = (u32)(lag_cap_ns >> 20);
		u32 w = (n + BOUND_SWEEP_BUDGET + gap - 1) / (BOUND_SWEEP_BUDGET + gap);
		if (w < 1) w = 1;
		sweep_win_stride = w > 1 ? (n + w - 1) / w : 0;
		sweep_win_count = w;
		w = (n + TICK_SCAN_BUDGET + gap - 1) / (TICK_SCAN_BUDGET + gap);
		if (w < 1) w = 1;
		scan_win_stride = w > 1 ? (n + w - 1) / w : 0;
		scan_win_count = w;
	}

	// THE BASE KNOB SET IS TOPOLOGY. slice: THE BASE OR 0.15 tau, WHICHEVER IS
	// SHORTER, tau's TERM CLAMPED [0.5ms, 8ms]. batch: THE BASE OR 1.5 tau,
	// CLAMPED [10ms, 80ms]. codel_thresh: 0.15 tau CLAMPED [2ms, 6ms]. AT THE 12C
	// REFERENCE (tau 13.3ms): 1ms, 20ms, 2ms.
	v = scale_tau(tau_ns, K_SLICE_CAP_Q16);
	if (v < 500000ULL)  v = 500000ULL;
	if (v > 8000000ULL) v = 8000000ULL;
	knobs_g.slice_ns = v < SLICE_BASE_NS ? v : SLICE_BASE_NS;

	v = scale_tau(tau_ns, K_BATCH_CAP_Q16);
	if (v < 10000000ULL) v = 10000000ULL;
	if (v > 80000000ULL) v = 80000000ULL;
	knobs_g.batch_slice_ns = v < BATCH_BASE_NS ? v : BATCH_BASE_NS;

	v = scale_tau(tau_ns, K_SOJOURN_Q16);
	if (v < 2000000ULL) v = 2000000ULL;
	if (v > 6000000ULL) v = 6000000ULL;
	knobs_g.codel_thresh_ns = v;
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

// THE RUN HABIT'S BUCKET: floor(log2(avg_run_ns / 1us)), CAPPED AT THE LAST
// BUCKET. 0 IS UNDER 2us, 15 IS 32ms AND OVER. A BOUNDED UNROLLED COMPARE
// CHAIN, SINCE BPF HAS NO COUNT-LEADING-ZEROS.
static __always_inline u32 ewma_bucket(u64 avg_ns)
{
	u64 us = avg_ns / 1000;
	u32 b = 0;
	#pragma unroll
	for (u32 i = 1; i < EWMA_HIST_BUCKETS; i++) {
		if (us >> i)
			b = i;
	}
	return b;
}

// TRACE: FAST 4-BYTE comm CHECK, CATCHING "panda" WITH NO MAP OVERHEAD.
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
// THE CALLER READS THE CLOCK AND PASSES IT, SO THE ONE READ THAT STAMPS
// THE WAIT BASE ALSO STAMPS THE ARRIVAL WHERE NO PICK STANDS BETWEEN THEM,
// AND FEEDS THE PICK'S ADMISSION WHERE THE PICK COMES SECOND.
static __always_inline u64 task_deadline(struct task_ctx *tctx, u64 now)
{
	if (!tctx->wait_since)
		tctx->wait_since = now;
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
// AND SOJOURN RESCUE. ADMISSION-BOUNDED: PAST ONE TARGET THE SPILL TAKES A
// NEAR SIBLING'S SEAT.
// THE CPU IS IDLE SO IT ENTERS dispatch() IMMEDIATELY AND DRAINS.
s32 BPF_STRUCT_OPS(panda_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;

	// THE SEAT LADDER: A PARTNER'S SYNC HANDOFF TAKES THE WAKER'S CORE, THEN PHI'S
	// R_eff WALK TAKES THE NEAREST IDLE CPU, AND ONLY WHEN THE WALK FINDS NONE
	// DOES AN UNCONGESTED HOME HOLD THE WAKEE (warm_seat_pick, BELOW THE WALKS).
	// ONE FETCH OF THE TASK'S CONTEXT FOR THE WHOLE DECISION. IT WAS FETCHED
	// AGAIN IN EACH BLOCK BELOW, UP TO FOUR bpf_task_storage_get CALLS ON ONE
	// WAKE; THE KERNEL'S RUN ACCOUNTING READ select_cpu AT 1,445 ns A CALL ON
	// THE WAKER'S OWN CRITICAL PATH, AND THE REPEATS WERE THE CHEAPEST CUT.
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (tctx) {
		tctx->sync_wake = (wake_flags & SCX_WAKE_SYNC) ? 1 : 0;
		tctx->fanout_wake = fanout_wake(p, wake_flags) ? 1 : 0;
		tctx->wake_waker = (u32)bpf_get_current_task_btf()->pid + 1;
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
		s32 waker_cpu = bpf_get_smp_processor_id();
		// ONE MAINTAINER FOR THE PAIR LEDGER. enqueue's update_pair_ledger
		// DOES NOT RUN WHEN select_cpu DISPATCHES, SO THIS PATH ADVANCES IT
		// THROUGH THE SAME FUNCTION.
		// THE WAKER IS current. ITS pid IS READ OFF THE TASK, THE SAME VALUE
		// bpf_get_current_pid_tgid() CARRIED IN ITS LOW WORD, SO THE LEDGER
		// ADVANCES AS BEFORE; WHERE THE VERIFIER INLINES
		// bpf_get_current_task_btf() THE HELPER CALL IS GONE.
		if (tctx)
			update_pair_ledger(tctx, bpf_get_current_task_btf()->pid);
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
		if (topo.nr_domains > 1 && is_handoff_partner(tctx) &&
		    (u64)waker_cpu < nr_cpu_ids &&
		    bpf_cpumask_test_cpu(waker_cpu, p->cpus_ptr)) {
			struct tuning_knobs *knobs = get_knobs();
			u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
			// THE WAIT BASE AND THE ADMISSION READ STOOD BACK TO BACK, ONE STORE
			// APART, SO ONE CLOCK SERVES BOTH. THE ARRIVAL KEEPS ITS OWN READ
			// AFTER THE INSERT: THE PICK BETWEEN THEM WALKS THE SPILL SEATS WHEN
			// THE WAKER'S SEAT IS PAST ITS CEILING.
			u64 now = bpf_ktime_get_ns();
			// THE WAKER'S CORE, NOT ITS CPU. THE SEAT ABOVE ASSUMES THE WAKER
			// LEAVES IN MICROSECONDS; A SERVER THAT REPLIES AND KEEPS WORKING
			// DOES NOT. THE FRAME'S HUB HELD ITS CPU 5.2 us AT THE MEDIAN PAST
			// EACH OF ITS FOUR REPLIES A FRAME WHILE THE SIMULATION THREAD WAITED
			// BEHIND IT, AND THE HUB CPU'S SMT SIBLING WAS IDLE AT 98.9 PERCENT
			// OF THEM: 5.24 us FROM WAKE TO RUN AGAINST EEVDF'S 1.44 ON THAT
			// SIBLING, ABOUT 12.5 us OF THE SIMULATION THREAD'S FRAME. SO THE
			// WAKER'S SEAT IS PRICED BY WHAT THE WAKER HAS LEFT OF ITS HABIT
			// AGAINST WHAT WAKING AN IDLE CPU COSTS, AND WHEN THE
			// WAKER'S SEAT IS DEARER THE WAKEE TAKES THE WAKER'S IDLE SIBLING:
			// THE SAME CORE AND CACHES THE CO-LOCATION IS FOR, WITHOUT THE WAIT.
			// A PIPE PAIR WHOSE WAKER BLOCKS AT ONCE PRICES NEAR ZERO AND KEEPS
			// THE SEAT BELOW. SLOT 0 OF THE RANK IS THE SMT SIBLING WHERE ITS
			// R_eff FRACTION IS 0; ON A PART WITHOUT SMT NOTHING CHANGES.
			{
				u32 skey = (u32)waker_cpu * MAX_AFFINITY_CANDIDATES;
				u32 *sib = bpf_map_lookup_elem(&affinity_rank, &skey);
				u32 *sfr = bpf_map_lookup_elem(&reff_frac, &skey);
				// THE WAKER IS current, SO WHAT IT HAS LEFT IS READ FROM ITS OWN
				// CPU'S HABIT SLOTS, NOT THROUGH seat_wait's REMOTE-RESIDENT
				// PATH: NO HABIT YET, OR PAST IT, READS AS NOT LEAVING, AS THE
				// GRANTED SLICE WOULD; A QUEUE ALREADY STANDING ON ITS SEAT ADDS.
				u32 wslot = cpu_slot((u32)waker_cpu);
				u64 wexp = run_expect_ns[wslot];
				u64 wran = now > run_start_ns[wslot] ? now - run_start_ns[wslot] : 0;
				bool waker_stays = !wexp || wran >= wexp ||
						   wexp - wran > WAKER_CORE_WAKE_NS ||
						   queue_wait(&pcpu_qclock[wslot], now) > WAKER_CORE_WAKE_NS;
				if (waker_stays && sib && sfr && *sfr == 0 && seat_ok((s32)*sib) &&
				    bpf_cpumask_test_cpu(*sib, p->cpus_ptr) &&
				    scx_bpf_test_and_clear_cpu_idle(*sib)) {
					s32 sc = (s32)*sib;
					if (!seat_handoff_fast(p, tctx, sc, knobs)) {
						// THE CLAIMED SIBLING HAS WORK QUEUED: SEAT BEHIND IT
						// AND WAKE IT, AS seat_task DOES FOR A WAKE THAT MAY
						// NOT CUT.
						u64 sdl = tctx ? task_deadline(tctx, now) : now;
						scx_bpf_dsq_insert_vtime(p, (u64)sc, sl, sdl, 0);
						qclock_arrive(tctx, (u64)sc, bpf_ktime_get_ns());
						scx_bpf_kick_cpu(sc, SCX_KICK_IDLE);
					}
					if (tctx)
						tctx->dispatch_path = 0;
					struct panda_stats *ss = get_stats();
					if (ss) {
						ss->nr_idle_hits += 1;
						ss->nr_dispatches += 1;
						cross_domain_bump(ss, XDOM_SEL_TIGHT,
								  tctx ? tctx->last_cpu : -1, sc);
					}
					return sc;
				}
			}
			u64 dl = tctx ? task_deadline(tctx, now) : now;
			s32 dst_cpu;
			u64 dst_dsq = pick_pcpu_dsq_with_spill(p, waker_cpu, p->cpus_ptr,
							       true, true, now, &dst_cpu);
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
			if (tctx)
				tctx->dispatch_path = 0;
			struct panda_stats *s = get_stats();
			if (s) {
				s->nr_idle_hits += 1;
				s->nr_dispatches += 1;
				cross_domain_bump(s, XDOM_SEL_TIGHT,
						  tctx ? tctx->last_cpu : -1,
						  dst_cpu);
			}
			return dst_cpu;
		}
		s32 anchor = seat_ok(prev_cpu) ? prev_cpu : waker_cpu;
		if ((u64)anchor < nr_cpu_ids) {
			// PHI PLACEMENT: THE WARM CORE IF IDLE, ELSE THE NEAREST IDLE
			// PEER IN R_eff ORDER.
			s32 target = phi_warm_target(anchor, p->cpus_ptr, false);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				s32 dst_cpu = target;
				if (!seat_handoff_fast(p, tctx, target, knobs)) {
					u64 sl = tctx ? task_slice(tctx, knobs)
						      : 1000000;
					// PHI DECIDES. THE WALK CLAIMED target'S IDLE BIT, SO target
					// IS THE SEAT. SEATING ANYWHERE ELSE LEAVES THE CLAIMED CPU
					// IDLE WITH ITS BIT CLEAR, INVISIBLE TO EVERY LATER WALK
					// UNTIL IT NEXT RESCHEDULES.
					u64 dst_dsq = pick_pcpu_dsq_with_spill(p, target, p->cpus_ptr, is_handoff_partner(tctx), false, bpf_ktime_get_ns(), &dst_cpu);
					u64 now = bpf_ktime_get_ns();
					u64 dl = tctx ? task_deadline(tctx, now) : now;
					// pick_pcpu_dsq_with_spill CAN REDIRECT dst_cpu OFF THE
					// VERIFIED-IDLE target ONTO A BUSY SEAT, WHERE SCX_KICK_IDLE
					// IS A NO-OP: PREEMPT WHEN THE SEAT MOVED AND THE WAKE MAY
					// CUT, IDLE OTHERWISE.
					seat_task(p, tctx, dst_cpu, target, dst_dsq, sl, dl,
						  wake_cuts(tctx),
						  dst_cpu != target && wake_cuts(tctx)
							  ? SCX_KICK_PREEMPT : SCX_KICK_IDLE, 0, now);
				}
				if (tctx) {
					tctx->dispatch_path = 0;
				}
				struct panda_stats *s = get_stats();
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
		// FORK SEED: A FRESHLY FORKED THREAD HAS last_cpu = -1 FROM enable(), SO
		// IT WOULD SKIP THIS WARM PATH AND TAKE THE NODE-WIDE dfl PICK, WHICH
		// SCATTERS IT ACROSS THE DOMAIN BOUNDARY. ANCHOR A NEVER-RAN TASK ON
		// prev_cpu -- THE PARENT'S CPU AT FORK -- SO IT TAKES THE SAME PRICED
		// WARM ROUTE AN ESTABLISHED TASK TAKES. NO FORK BRANCH, NO BAIL GATE.
		s32 anchor = (tctx && tctx->last_cpu >= 0) ? tctx->last_cpu : prev_cpu;
		if (!last_cpu_idle_miss && tctx && seat_ok(anchor) &&
		    bpf_cpumask_test_cpu(anchor, p->cpus_ptr)) {
			// PHI PLACEMENT: THE WARM CORE IF IDLE, ELSE THE NEAREST IDLE
			// PEER IN R_eff ORDER. THE CLAIMED target IS THE SEAT, AS ON
			// THE SYNC PATH ABOVE.
			// THE ANCHOR PASSED ITS MASK TEST ON ENTRY TO THIS BLOCK, SO THE WALK
			// DOES NOT ASK IT AGAIN: ONE KFUNC ON EVERY WAKE THAT ENTERS HERE.
			s32 target = phi_warm_target(anchor, p->cpus_ptr, true);
			if (target >= 0) {
				struct tuning_knobs *knobs = get_knobs();
				s32 seat_cpu = target;
				if (!seat_handoff_fast(p, tctx, target, knobs)) {
					u64 sl = task_slice(tctx, knobs);
					u64 now = bpf_ktime_get_ns();
					u64 dl = task_deadline(tctx, now);
					u64 seat_dsq = pick_pcpu_dsq_with_spill(p, target, p->cpus_ptr, is_handoff_partner(tctx), false, now, &seat_cpu);
					// THE SPILL CAN SEAT OFF THE VERIFIED-IDLE target ONTO A
					// BUSY SIBLING: PREEMPT WHEN THE SEAT MOVED AND THE WAKE MAY
					// CUT, IDLE OTHERWISE, WHICH IS THE WAIT A WAKE THAT MAY NOT
					// CUT IS GIVEN. THE WAIT BASE AND THE PICK SHARE ONE CLOCK; THE
					// ARRIVAL IS READ AFTER THE PICK, AS AT THE OTHER SEATS.
					seat_task(p, tctx, seat_cpu, target, seat_dsq, sl, dl,
						  wake_cuts(tctx),
						  seat_cpu != target && wake_cuts(tctx)
							  ? SCX_KICK_PREEMPT : SCX_KICK_IDLE, 0,
						  bpf_ktime_get_ns());
				}
				tctx->dispatch_path = 0;
				struct panda_stats *s = get_stats();
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
	// THE WAKE IS READ FROM wake_flags. select_cpu RUNS FOR A WAKE, A FORK OR
	// AN EXEC AND THE KERNEL SAYS WHICH; ran_since_wake CANNOT, SINCE runnable()
	// CLEARS IT ONLY AFTER select_cpu HAS RETURNED, AND READ HERE IT WAS THE
	// TASK'S LAST RUN: NO WAKE BUT A TASK'S FIRST EVER HELD, AND A PARTNER'S
	// ANCHORED ON last_cpu WHERE THE WAKE ARM ANCHORS ON home_cpu.
	// A WAKE THAT MAY NOT CUT IS NOT HELD, BY enqueue's OWN RULE AT TIER 0,
	// WHERE THIS HOLD LANDS: HELD HERE IT WOULD ONLY BE RELEASED THERE TO THE
	// NODE-WIDE IDLE PICK, WHICH dfl MAKES BELOW WITH A DIRECT HAND-OFF.
	{
		bool wake = wake_flags & SCX_WAKE_TTWU;
		s32 hold = (wake && !wake_cuts(tctx)) ? -1
			 : warm_seat_pick(p, tctx, get_knobs(), wake);
		if (hold >= 0)
			return hold;
	}

	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
	s32 dst_cpu = cpu;

	if (is_idle) {
		struct tuning_knobs *knobs = get_knobs();
		if (!seat_handoff_fast(p, tctx, cpu, knobs)) {
			u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;

			// PER-CPU DSQ PLACEMENT WITH L2/R_EFF SPILL. CACHE-HOT IF cpu
			// HAS ROOM; SIBLING PER-CPU DSQ NEXT (REACHED BY DISPATCH STEP 0
			// ON SIBLING OR STEP 1 L2 STEAL); ELSE THE OWN SEAT OVER TARGET.
			u64 dst_dsq = pick_pcpu_dsq_with_spill(p, cpu, p->cpus_ptr, is_handoff_partner(tctx), false, bpf_ktime_get_ns(), &dst_cpu);
			u64 now = bpf_ktime_get_ns();
			u64 dl = tctx ? task_deadline(tctx, now) : now;
			// `cpu` IS THE VERIFIED-IDLE dfl PICK. THE SPILL CAN REDIRECT dst_cpu
			// ONTO A BUSY SIBLING: PREEMPT WHEN THE SEAT MOVED AND THE WAKE MAY
			// CUT, IDLE OTHERWISE.
			seat_task(p, tctx, dst_cpu, cpu, dst_dsq, sl, dl, wake_cuts(tctx),
				  dst_cpu != cpu && wake_cuts(tctx)
					  ? SCX_KICK_PREEMPT : SCX_KICK_IDLE, 0, now);
		}

		if (tctx) {
			tctx->dispatch_path = 0;
		}

		struct panda_stats *s = get_stats();
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
void BPF_STRUCT_OPS(panda_enqueue, struct task_struct *p,
		    u64 enq_flags)
{
	// THE TASK'S CPU CANNOT MOVE WHILE enqueue HOLDS ITS rq, SO IT IS READ
	// ONCE; TIER 3 READ IT TWICE MORE. ITS NODE FEEDS ONLY THE TWO NODE-WIDE
	// PICKS AND IS READ AT THE FIRST, WHICH EVERY PATH TO THE SECOND PASSES,
	// SO A TIER 0 HOLD AND A TIER 1 WALK HIT DO NOT PAY FOR IT.
	s32 tcpu = scx_bpf_task_cpu(p);
	s32 node = 0;

	struct task_ctx *tctx = lookup_task_ctx(p);

	struct tuning_knobs *knobs = get_knobs();
	u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;
	u64 dl;

	// CLASSIFY: WAKEUP VS RE-ENQUEUE
	bool is_wakeup = tctx && !tctx->ran_since_wake;

	// A CUT'S WAKEE, PREEMPTED BY ITS OWN CUT'S KICK (CUT_SELF_KICK_NS), GOES
	// BACK TO THE HEAD OF THIS CPU'S LOCAL DSQ AND RUNS ON. THE TASK'S STAMP IS
	// THE FILTER AND IS SPENT BY ONE enqueue; THE SEAT'S LINE IS READ ONLY FOR
	// A TASK THAT CARRIES ONE.
	if (tctx && tctx->cut_at) {
		u64 cut_at = tctx->cut_at;
		tctx->cut_at = 0;
		if (!is_wakeup && (u32)tcpu < nr_cpu_ids &&
		    pcpu_qclock[cpu_slot((u32)tcpu)].cut_pid == p->pid &&
		    bpf_ktime_get_ns() - cut_at < CUT_SELF_KICK_NS) {
			scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, sl,
					   enq_flags | SCX_ENQ_HEAD);
			struct panda_stats *cs = get_stats();
			if (cs) {
				cs->nr_cut_reseat += 1;
				cs->nr_enq_requeue += 1;
			}
			return;
		}
	}

	// FLOW SIGNATURE: RECORD THIS WAKEUP'S WAKER CPU IN THE PERSISTED SHAPE
	// BITMAP (CLASSIFY ONCE BY PARTNER CARDINALITY, FREEZE AT MATURITY). THE
	// WAKER IS THE ENQUEUEING CPU.
	// SCX_OPS_ALLOW_QUEUED_WAKEUP IS ON, SO A WAKE THE KERNEL QUEUES ON THE
	// WAKEE'S CPU (ACROSS AN LLC, OR ONTO AN IDLE CPU) RUNS THIS THERE, WHERE
	// current IS THAT CPU'S TASK. THE WAKER IS READ FROM select_cpu's STAMP. A
	// WAKE THAT SKIPPED select_cpu (ONE ALLOWED CPU, MIGRATION DISABLED) HAS NO
	// STAMP AND READS current: THE WAKER WHEN THE WAKE WAS NOT QUEUED, THE IDLE
	// TASK (pid 0, WHICH THE LEDGER IGNORES) OR THE RESIDENT WHEN IT WAS, AS AN
	// IRQ WAKE ALREADY READS THE TASK IT INTERRUPTED.
	if (tctx && is_wakeup)
		update_pair_ledger(tctx, tctx->wake_waker
					 ? (s32)(tctx->wake_waker - 1)
					 : bpf_get_current_task_btf()->pid);

	// TIER 1: IDLE CPU -> THAT CPU'S PER-CPU DSQ + KICK. PLACEMENT IS THE R_eff
	// WALK, WITH NO CLASS GATE IN FRONT OF IT. find_idle_by_affinity WALKS
	// affinity_rank IN ASCENDING R_eff, SO DISTANCE DEGRADES CONTINUOUSLY RATHER
	// THAN FALLING OFF A CLIFF INTO AN UNORDERED NODE-WIDE PICK, AND THE BIAS IS
	// EXPRESSED BY *WHICH* IDLE CPU WINS. affinity_search_online IS TAU-DERIVED,
	// 3 AT 12C AND 8 AT 32C, SO THE BUDGET SCALES WITHOUT A KNOB.
	// THE NODE-WIDE pick_idle_cpu BELOW IS THE FALLBACK WHEN THE WALK MISSES.
	s32 cpu = -1;
	if (tctx)
		cpu = find_idle_by_affinity(tctx->last_cpu, p->cpus_ptr, false);
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
		// 2. HELD AT A BUSY HOME IT WAITED OUT THE RESIDENT WHILE ANOTHER CPU
		// IDLED, AND heavy's JOB WAKE p99 READ 339 us AGAINST 52.
		{
			s32 hold = (is_wakeup && !wake_cuts(tctx)) ? -1
				 : warm_seat_pick(p, tctx, knobs, is_wakeup);
			if (hold >= 0) {
				// ONE CLOCK STAMPS THE WAIT BASE, THE PAIR-WARM MARK AND THE ARRIVAL.
				// ONLY THE KICK PRICE, WHICH KEEPS ITS OWN READ, AND THE INSERT
				// STAND BETWEEN THE FIRST STAMP AND THE LAST.
				u64 hnow = bpf_ktime_get_ns();
				u64 hdl = task_deadline(tctx, hnow);
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
				u64 hold_kick = requeue_kick_flag(tctx, hold, is_wakeup, false);
				if (seat_task(p, tctx, hold, -1, (u64)hold, sl, hdl,
					      is_wakeup && wake_cuts(tctx), hold_kick,
					      enq_flags, hnow) == SEAT_CUT)
					hold_kick = SCX_KICK_PREEMPT;
				tctx->dispatch_path = 1;
				struct panda_stats *s = get_stats();
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
		node = __COMPAT_scx_bpf_cpu_node(tcpu);
		if (node < 0 || (u32)node >= nr_nodes)
			node = 0;
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	}
	if (cpu >= 0 && (u64)cpu < nr_cpu_ids) {
		// SEAT THE WAKEE ON THAT CPU'S OWN PER-CPU DSQ AND KICK IT. KICK ==
		// DRAIN IDENTITY -- THE KICKED CPU IS THE ONE THAT DISPATCHES IT.
		// STEP 1's R_eff STEAL STILL RELIEVES THE SEAT IF IT AGES PAST THE PHI
		// THRESHOLD.
		u64 tier1_dsq = (u64)cpu;
		u64 now = bpf_ktime_get_ns();
		dl = tctx ? task_deadline(tctx, now) : now;

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
		u64 kick_flag = requeue_kick_flag(tctx, cpu, is_wakeup, false);
		if (seat_task(p, tctx, cpu, cpu, tier1_dsq, sl, dl,
			      is_wakeup && wake_cuts(tctx), kick_flag,
			      enq_flags, now) == SEAT_CUT)
			kick_flag = SCX_KICK_PREEMPT;

		if (tctx) {
			tctx->dispatch_path = 0;
		}

		struct panda_stats *s = get_stats();
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
		cpu = seat_ok(tctx->last_cpu)
		    ? tctx->last_cpu
		    : __COMPAT_scx_bpf_pick_any_cpu_node(p->cpus_ptr, node, 0);
		if (seat_ok(cpu)) {
			// A FAN-OUT WAKE THAT REACHES THIS TIER FOUND NO CPU IDLE ON THE
			// NODE. QUEUED ON ITS WARM SEAT IT WAITS OUT A WORKER'S STINT OR
			// THE BAND WHILE A SEAT BESIDE IT HOLDS A RESIDENT THAT HAS HAD
			// ITS FIRST TARGET AND NO HEAD. IT TAKES THAT SEAT'S QUEUE AND
			// PREEMPTS (spent_seat); WITH NONE IT IS SEATED AS BEFORE.
			if (is_wakeup && tctx->fanout_wake && !is_migration_disabled(p)) {
				u64 fnow = bpf_ktime_get_ns();
				s32 spent = spent_seat(p, cpu,
						       tctx->wake_waker ? tctx->wake_waker - 1 : 0,
						       fnow);
				if (spent >= 0) {
					dl = task_deadline(tctx, fnow);
					// IT TAKES THE SEAT'S QUEUE, WHICH seat_spent FOUND EMPTY,
					// AND THE KICK SENDS THE RESIDENT OFF: NOT THE LOCAL DSQ,
					// WHERE A CUT ARRIVING NEXT QUEUES BEHIND IT AND NO THIEF
					// OR CLOCK REACHES IT. MEASURED: ON THE LOCAL DSQ
					// CONTENDED READ 422 FPS AND ITS 0.1% LOW 222, ON THE
					// SEAT'S QUEUE 425 AND 260.
					seat_task(p, tctx, spent, -1, (u64)spent, sl, dl,
						  false, SCX_KICK_PREEMPT, enq_flags, fnow);
					tctx->dispatch_path = 1;
					struct panda_stats *fs = get_stats();
					if (fs) {
						fs->nr_shared += 1;
						fs->nr_dispatches += 1;
						fs->nr_hard_kicks += 1;
						fs->nr_enq_wakeup += 1;
					}
					return;
				}
			}
			s32 t2_cpu;
			u64 tier2_dsq = pick_pcpu_dsq_with_spill(p, cpu, p->cpus_ptr, is_handoff_partner(tctx), false, bpf_ktime_get_ns(), &t2_cpu);

			u64 now = bpf_ktime_get_ns();
			dl = task_deadline(tctx, now);

			// THE KICK GOES TO t2_cpu, NOT `cpu` -- THEY DIFFER WHENEVER
			// THE SPILL FIRES, AND THE HELPER TESTS THE SEAT THAT WILL
			// ACTUALLY HOLD THE TASK.
			u64 kick_flag = requeue_kick_flag(tctx, t2_cpu, is_wakeup, false);
			if (seat_task(p, tctx, t2_cpu, -1, tier2_dsq, sl, dl,
				      is_wakeup && wake_cuts(tctx), kick_flag,
				      enq_flags, now) == SEAT_CUT)
				kick_flag = SCX_KICK_PREEMPT;
			tctx->dispatch_path = 1;

			struct panda_stats *s = get_stats();
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

	// TIER 3: THE TASK'S OWN CPU. A PLAIN REQUEUE TAKES THAT CPU'S LANE, A WAKE
	// WITH NO WARM CPU TO ANCHOR ON ITS SEAT, EACH OLDEST-FIRST. A REQUEUED TASK
	// WAS PASSED OVER OR CUT, NOT MOVED, SO IT RESUMES WHERE ITS CACHE IS, AS
	// UNDER EEVDF, AND A MIGRATION-DISABLED TASK WAITS ON THE ONE CPU IT MAY
	// LEAVE FROM. ON THE LANE IT WAITS BEHIND NO WAKE AND NO WAKE BEHIND IT:
	// dispatch() SERVES THE SEAT FIRST UNTIL THE LANE HAS WAITED PAST THE LIVE
	// TARGET. A CPU THAT RUNS DRY TAKES IT BY THE STEAL, AND THE TICK AND THE
	// SWEEP BOUND ITS WAIT. THE KICK IS PRICED AS AT EVERY OTHER TIER: A REQUEUE
	// ON THE CPU RUNNING THIS enqueue IS SILENT, SINCE THIS CPU REACHES
	// dispatch() ON ITS OWN.
	s32 t3_cpu = allowed_seat(p, tcpu);
	u64 t3_dsq = is_wakeup ? (u64)t3_cpu : lane_dsq((u32)t3_cpu);
	u64 now = bpf_ktime_get_ns();
	dl = tctx ? task_deadline(tctx, now) : now;
	u64 kick_flag = requeue_kick_flag(tctx, t3_cpu, is_wakeup, !is_wakeup);
	if (seat_task(p, tctx, t3_cpu, -1, t3_dsq, sl, dl,
			  is_wakeup && wake_cuts(tctx), kick_flag,
			  enq_flags, now) == SEAT_CUT)
		kick_flag = SCX_KICK_PREEMPT;

#if TRACE_SCHED
	if (is_sched_task(p))
		bpf_printk("PAND: enq tier3 pid=%d cpu=%d", p->pid, t3_cpu);
#endif

	if (tctx)
		tctx->dispatch_path = is_wakeup ? 1 : 2;

	struct panda_stats *s = get_stats();
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

// THE BAND A NON-RT RESIDENT ANSWERS TO: THE OSCILLATOR'S FLOOR, NOT THE LIVE
// TARGET. MEASURED ON FRAME CONTENDED AT N=3: AT THE TARGET THE 1% LOW READ
// 287 AND THE 0.1% LOW 248; AT THE FLOOR, WITH THE RESIDENT TERM IN
// seat_wait CAPPED AT THE SAME BAND, 297 AND 254, STUTTERS ZERO, HEAVY HELD.
// A FAN-OUT WAKE QUEUED BEHIND A HOG IS SERVED AT THE FLOOR; THE PACE, THE
// TARGET EVERY OTHER SITE PRICES AGAINST, AND lag_cap_ns ARE UNCHANGED. THE
// TARGET PINNED TO THE FLOOR AT EVERY SITE WAS MEASURED AND LOST THE TAIL.
static __always_inline u64 sweep_band_ns(void)
{
	return codel_target_floor_ns;
}

// THE PACE OF THE SWEEP'S ACT ON ONE QUEUE: CoDel's CONTROL LAW SCHEDULES THE
// NEXT ACT AT pace / sqrt(acts). THE PACE STAYS THE LIVE TARGET; PACING AT
// THE FLOOR, WITH THE WINDOW STEPPING EVERY 131 us, WAS MEASURED AND MOVED
// NEITHER THE AVERAGE NOR THE WAKE TAIL.
static __always_inline u64 sweep_pace_ns(void)
{
	return codel_target_ns;
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

// UNIFIED SOJOURN BOUND SWEEP -- THE BACKSTOP UNDER THE TICK TOWER, NEVER
// ITS REPLACEMENT. ANY CPU WHOSE PER-CPU DSQ HEAD HAS WAITED >= lag_cap_ns
// GETS A PREEMPT KICK, NO EXEMPTION. IT RUNS FROM DISPATCH ON EVERY CPU,
// SO A CPU WALLED OFF BY A NON-YIELDING RESIDENT IS RESCUED BY ANY OTHER
// CPU's DISPATCH -- OFF THE HELD CPU's OWN TICK, SO NO_HZ_FULL CANNOT
// SUPPRESS IT. THIS IS THE FREEZE FIX: THE TICK TOWER'S 5ms BAND IS THE FAST
// PATH, THIS IS THE TICK-INDEPENDENT GUARANTEE BENEATH IT. ROTATING BUDGET
// WINDOWS: O(1) PER DISPATCH. THE WINDOW STARTS AT THE CLOCK'S NUMBER PLUS
// THIS CPU'S WINDOW'S OFFSET, sweep_win_count WINDOWS ROUND THE MACHINE, SO NO
// SEAT IS OUT OF EVERY WINDOW FOR LONGER THAN lag_cap_ns AT ANY WIDTH.
// UNCONDITIONAL AT DISPATCH ENTRY -- MEASURED: GATED ON A STEP-0 MISS, EVERY
// CPU's STEP 0 KEEPS HITTING UNDER SATURATION AND THE ENFORCER GOES DORMANT
// SYSTEM-WIDE. DO NOT REORDER.
// A SWEPT CPU THAT HAS GONE OFFLINE IS NOT KICKED: IT DISPATCHES NOTHING. WHAT
// WAS SEATED ON IT BEFORE IT WENT DOWN IS TAKEN HERE INSTEAD, ITS SEAT THEN ITS
// LANE, ONE TASK A DISPATCH, AND THE SWEEP RETURNS TRUE: THIS DISPATCH HAS ITS
// TASK. THE LOADER'S ROWS LIST ONLINE CPUs ONLY, SO NO STEAL WALK REACHES AN
// OFFLINE CPU'S QUEUES, AND ITS OWN DISPATCH MAY NOT TAKE A TASK THAT BELONGS
// TO ANOTHER CPU'S rq ONCE ITS OWN IS OFFLINE. THE ONLINE BYTE IS READ ONLY FOR
// A QUEUE THAT HOLDS WORK.
static __always_inline bool sweep_bound_preempt(u64 now, u32 self)
{
	u32 nr = nr_cpu_ids;
	if (nr == 0)
		return false;
	u32 base = (u32)(now >> 20) + (self % sweep_win_count) * sweep_win_stride;
	#pragma unroll
	for (u32 i = 0; i < BOUND_SWEEP_BUDGET; i++) {
		u32 c = (base + i) % nr;
		if (c == self)
			continue;
		u64 w = queue_wait(&pcpu_qclock[cpu_slot(c)], now);
		struct queue_clock *lq = &lane_qclock[cpu_slot(c)];
		u64 lw = queue_wait(lq, now);
		if ((w | lw) && !cpu_up[cpu_slot(c)]) {
			if (scx_bpf_dsq_move_to_local((u64)c, 0) ||
			    scx_bpf_dsq_move_to_local(lane_dsq(c), 0))
				return true;
			continue;
		}
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
		if (queue_act(lq, lw, lag_cap_ns, 0, now)) {
			scx_bpf_kick_cpu((s32)c, SCX_KICK_PREEMPT);
			continue;
		}
		if (!resident_owed(c, now) &&
			queue_act(&pcpu_qclock[cpu_slot(c)], w, sweep_band_ns(),
				  sweep_pace_ns(), now))
			scx_bpf_kick_cpu((s32)c, SCX_KICK_PREEMPT);
	}
	return false;
}

// STEP 1 STEAL-WALK STATE, CARRIED ACROSS bpf_loop() ITERATIONS.
//
// THE WALK IS bpf_loop() AND NOT A BOUNDED for SO THE VERIFIER CHECKS THE BODY
// ONCE INSTEAD OF ONCE PER CANDIDATE. MAX_AFFINITY_CANDIDATES IS 128 AT COMPILE
// TIME WHILE pcpu_spill_search_budget CLAMPS THE WALK TO ~6 AT 12C, AND A
// VERIFIER THAT CANNOT FOLD nr_cpu_ids MUST ASSUME ALL 128. THAT GAP -- NOT THE
// RUNTIME COST -- PUSHED panda_dispatch PAST THE 1M INSTRUCTION CEILING
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
			// ORDER IS THE DISTANCE AND THE BUDGET ITS REACH. A LONE TASK ON A
			// BUSY PEER BESIDE AN IDLE CPU IS THE SHAPE silica's STORM TAIL WAS
			// MADE OF. A BUSY CPU GIVES UP prev FOR A HEAD THAT HAS WAITED THE
			// BASE COST PLUS THE DISTANCE. THE AGE, NEVER THE RESIDENT'S
			// REMAINING HABIT: THE STEAL PRICED BY THAT WAS MEASURED AND LOST.
			// PAST THE BUSY BUDGET A LANE IS PRICED AS A BUSY THIEF PRICES IT,
			// EVEN FOR A CPU ABOUT TO IDLE: A FAR LANE HOLDS HOGS AS WELL AS
			// DISPLACED WORK, AND TAKING ONE THERE AT THE BASE COST MOVED HOGS
			// ACROSS THE BOX (scale's long-run and burst p99 1 TO 2 ms).
			bool far_lane = c->lanes && c->checked >= pcpu_spill_search_budget;
			u64 bound = phi_base_cost_ns +
				    ((c->would_idle && !far_lane) ? 0 : price) + pair_hold;
			if (peer_wait >= bound) {
				// THE MOVE IS TAKEN IN THE WALK, SO A RACE LOST TO ANOTHER
				// THIEF OR TO THE PEER'S OWN STEP 0 WALKS ON TO THE NEXT
				// QUALIFYING PEER INSTEAD OF ENDING THE SCAN.
				if (scx_bpf_dsq_move_to_local(pdsq, 0)) {
					c->best_peer = (s32)peer;
					c->rescue = c->lanes && peer_wait > codel_target_ns;
					return 1;
				}
				c->lost += 1;
			} else {
				// A HEAD FOUND WAITING AND LEFT, COUNTED BY THE BOUND THAT
				// LEFT IT: THE PRICES' REFUSAL COUNTERS. WRITTEN HERE AND NOT
				// CARRIED IN THE WALK'S STATE: THREE COUNTS THERE TOOK THE
				// VERIFIER FROM 43,000 INSTRUCTIONS OF dispatch TO 123,000.
				struct panda_stats *rs = get_stats();
				if (rs) {
					u32 idx = ((c->lanes ? 2 : 0) + (c->would_idle ? 0 : 1)) *
						  STEAL_REF_ROW +
						  (peer_wait < phi_base_cost_ns ? STEAL_REF_YOUNG
						   : peer_wait < bound - pair_hold ? STEAL_REF_PRICE
						   : STEAL_REF_PAIR);
					rs->nr_steal_refused[idx & (STEAL_REF_SLOTS - 1)] += 1;
				}
				// THE SECOND LOOK'S MARK: A SEAT'S HEAD A CPU ABOUT TO IDLE
				// LEAVES. THE LOOK'S OWN BOUND IS THE BASE COST AND THE HOLD,
				// THE HOLD COUNTED NO DEARER THAN THE BASE COST; THE FREEING
				// LOOK SETS THE WINDOW'S END, THE LATEST OF THE HEADS IT
				// LEAVES TO REACH IT. A HEAD HELD PAST THAT IS LEFT AS IT WAS.
				if (c->would_idle && !c->lanes) {
					u64 look_bound = phi_base_cost_ns +
						(pair_hold < phi_base_cost_ns ? pair_hold
									     : phi_base_cost_ns);
					if (peer_wait < look_bound) {
						struct steal_look *lk =
							&steal_look[cpu_slot(c->my_cpu)];
						if (lk->first) {
							u64 due = c->now + (look_bound - peer_wait);
							if (lk->left_at != c->now || due > lk->until)
								lk->until = due;
						}
						lk->left_at = c->now;
					}
				}
			}
		}
		if (++c->checked >= c->budget)
			return 1;
	return 0;
}

// A LANE THAT WAITED PAST THE LIVE TARGET WAS SERVED: THE OSCILLATOR'S FORCING
// TERM, THE EVENT THE DOMAIN QUEUE'S AGED SERVE COUNTED. EVERY DISPATCH THAT
// SERVES ONE, ITS OWN OR A PEER'S, IS A RESCUE, AND THE RESCUE RATE IS WHAT
// PULLS THE TARGET DOWN UNDER LOAD. A SEAT SERVED LATE IS NOT ONE: THE RESCUE
// MEASURES THE REQUEUE CLASS'S BACKLOG. FIXING THE TARGET AT ITS EQUILIBRIUM
// INSTEAD BROKE THE 8C LATENCY PROBE.
static __always_inline void rescue_served(struct panda_stats *s)
{
	if (s)
		s->nr_rescue += 1;
	__sync_fetch_and_add(&global_rescue_count, 1);
}

// ONE R_eff STEAL WALK OVER THE PEERS' SEATS, OR THEIR LANES. TRUE IF A TASK
// MOVED. SINGLE LOOP OVER affinity_rank: SLOT 0 IS THE L2 SIBLING (LOWEST
// R_EFF), SLOTS 1+ ARE R_EFF-RANKED PEERS, CROSS-DOMAIN INCLUDED, AND THE RANK
// IS DISTANCE-ORDERED, SO THE FIRST QUALIFYING PEER IS THE CLOSEST -- MIN-COST
// FLOW. A BUSY CPU's BUDGET IS pcpu_spill_search_budget (nr_cpu_ids/2 CLAMPED
// TO [6, MAX_AFFINITY_CANDIDATES]), MATCHING THE ENQUEUE-SIDE SPILL HELPER. A
// CPU ABOUT TO IDLE WALKS THE WHOLE RANK: IT IS ON NO WAKE PATH, AN EMPTY PEER
// COSTS ONE queue_wait READ, AND AT 12C SIX SLOTS REACH ONE PEER ACROSS THE
// L3. ON frame heavy 34 PERCENT OF THE WAKES OVER 100 us WAITED WITH AN IDLE
// CPU FREE, AGAINST 27 UNDER THE DOMAIN QUEUE, WHOSE DRAIN REACHED THE OTHER L3
// WHOLE.
static __always_inline bool steal_from(s32 cpu, u64 now, bool would_idle,
					   bool lanes)
{
	u32 my_cpu = (u32)cpu;
	struct steal_scan_ctx sctx = {
		.now = now, .base = my_cpu * MAX_AFFINITY_CANDIDATES,
		.my_cpu = my_cpu, .checked = 0,
		.budget = would_idle ? nr_cpu_ids : pcpu_spill_search_budget,
		.best_peer = -1, .lost = 0,
		.would_idle = would_idle, .lanes = lanes, .rescue = false,
	};
	bpf_loop(MAX_AFFINITY_CANDIDATES, steal_scan_step, &sctx, 0);
	if (!sctx.lost && sctx.best_peer < 0)
		return false;
	struct panda_stats *s = get_stats();
	if (s) {
		s->nr_steal_lost += sctx.lost;
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
void BPF_STRUCT_OPS(panda_dispatch, s32 cpu, struct task_struct *prev)
{
	struct panda_stats *s;
	u64 now = bpf_ktime_get_ns();

	// UNIFIED BOUND, FIRST: RESCUE ANY CPU WHOSE PER-CPU DSQ HEAD HAS WAITED
	// PAST lag_cap_ns, BEFORE THIS CPU RUNS ITS OWN PLACEMENT WATERFALL. A HARD
	// INVARIANT AHEAD OF PLACEMENT, RUN OFF ANOTHER CPU'S DISPATCH SO THE HELD
	// CPU'S OWN TICK IS NOT NEEDED. UNCONDITIONAL AND NOT TO BE REORDERED.
	if (sweep_bound_preempt(now, (u32)cpu)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

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
	// PUT THERE IS NOT PASSED FOR A REQUEUE: WITHOUT IT ipc's 12C PIPE p99 READ
	// 551 us AGAINST 15. PAST lag_cap_ns THE LANE IS SERVED ANYWAY, SO THE
	// STARVATION BOUND STANDS.
	u64 lane_wait = queue_wait(&lane_qclock[slot], now);
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
	// THE FREEING LOOK: A TASK JUST LEFT THIS CPU. THE WALK READS WHETHER IT
	// IS ONE FROM THIS CPU'S LINE, AND ONLY A CPU ABOUT TO IDLE WRITES IT.
	struct steal_look *lk = &steal_look[slot];
	if (would_idle)
		lk->first = prev != NULL;

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

	// THE SECOND LOOK: THIS CPU IS ABOUT TO IDLE AND ITS WALK LEFT A SEAT'S
	// HEAD UNDER THE LOOK'S BOUND, INSIDE THE WINDOW ITS FREEING LOOK OPENED.
	// SCX_KICK_IDLE ON ITSELF: THE KERNEL FINISHES THIS CYCLE, PICKS THE IDLE
	// TASK AND RESCHEDULES IT, AND dispatch() RUNS AGAIN A MICROSECOND OR TWO
	// LATER. A CPU GIVEN WORK IN BETWEEN IS NOT IDLE AND IS NOT KICKED.
	if (would_idle && lk->left_at == now && now < lk->until) {
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);
		return;
	}

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

// RUNNABLE: TASK WAKES UP -- THE WAKE STAMP AND ran_since_wake.
// NOTHING HERE TOUCHES THE OSCILLATOR. A WAKE INTO A PARKED CONTROLLER USED TO
// UN-PARK IT FROM WHATEVER CPU THE WAKE RAN ON AND SEND CPU 0 A PREEMPT KICK.
// A PARKED TARGET SITS ON ITS EQUILIBRIUM WITH NO VELOCITY, SO UNTIL A RESCUE
// ARRIVES THE RECOMPUTE THE UN-PARK ASKED FOR MOVES NOTHING, AND THE KICK RAN
// NO RECOMPUTE: THAT IS THE TICK'S. IT PREEMPTED CPU 0'S RESIDENT OR WOKE CPU 0
// FROM IDLE. THE CPU-0 TICK'S OWN DETECTOR UN-PARKS ON THE FIRST RESCUE.
void BPF_STRUCT_OPS(panda_runnable, struct task_struct *p,
		    u64 enq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	u64 now = bpf_ktime_get_ns();
	tctx->ran_since_wake = false;

	// last_woke_at HAS ONE JOB: WAKE LATENCY. STAMPED HERE, READ AND CLEARED IN
	// running(). NOTHING ELSE READS IT.
	tctx->last_woke_at = now;
	tctx->awake_since = now;

	// TIER IS TWO DECLARATIONS, STATED DIRECTLY RATHER THAN SCORED:
	//   PF_WQ_WORKER     -> INTERACTIVE    (USERSPACE BLOCKS ON THESE)
	//   EVERYTHING ELSE  -> BATCH
	// THERE IS NO RT BRANCH BECAUSE IT CANNOT BE TAKEN. sched_ext SITS BELOW RT
	// AND DEADLINE IN THE CLASS HIERARCHY AND IS HANDED ONLY SCHED_NORMAL,
	// SCHED_BATCH AND SCHED_IDLE, SO AN RT TASK NEVER REACHES THESE OPS.
}

// RUNNING: TASK STARTS EXECUTING -- RECORD WAKE LATENCY, SET RAN-SINCE-WAKE
void BPF_STRUCT_OPS(panda_running, struct task_struct *p)
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

	// THE SEAT'S TWO STAMPS, READ REMOTELY BY seat_wait(): WHEN THIS RUN BEGAN
	// AND WHAT THIS TASK'S HABIT SAYS IT WILL TAKE.
	{
		u32 slot = cpu_slot(bpf_get_smp_processor_id());
		run_start_ns[slot] = now;
		run_expect_ns[slot] = tctx->avg_run_ns;
		run_awake_ns[slot] = tctx->awake_since;
		if (tctx->awake_since && now > tctx->awake_since &&
		    now - tctx->awake_since >= lag_cap_ns)
			unslept_ran_ns[slot] = now;
	}
	tctx->run_exec_at = p->se.sum_exec_runtime;   // service base, see stopping()
	tctx->ran_since_wake = true;   // is_wakeup = !ran_since_wake
	tctx->sync_wake = 0;
	tctx->fanout_wake = 0;
	tctx->wake_waker = 0;
	if (tctx->handoff_seat) {
		// A DIRECT HAND-OFF'S SOJOURN, WRITTEN BY THE SEAT (seat_handoff_fast).
		struct queue_clock *hq = qclock_of((u64)(tctx->handoff_seat - 1));
		tctx->handoff_seat = 0;
		if (hq) {
			hq->progress_ns = now;
			if (tctx->wait_since && now > tctx->wait_since)
				hq->last_sojourn_ns = now - tctx->wait_since;
		}
	}
	qclock_depart(tctx, now, true);   // LEFT ITS QUEUE TO RUN -- A SOJOURN
	tctx->wait_since = 0;          // WAIT ENDED -- RELEASE THE SOJOURN CLAIM

	// WAKEUP-TO-RUN LATENCY, RECORDED ONCE PER WAKEUP: last_woke_at IS CLEARED
	// AFTER THE READ.
	if (tctx->last_woke_at && now > tctx->last_woke_at) {
		u64 wake_lat = now - tctx->last_woke_at;
		u8 path = tctx->dispatch_path;

		tctx->last_woke_at = 0;

		struct panda_stats *s = get_stats();
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
	}

	struct tuning_knobs *knobs = get_knobs();
	scx_bpf_task_set_slice(p, task_slice(tctx, knobs));
}

// STOPPING: TASK YIELDS CPU -- CACHE THE WEIGHT, PIN THE HOME, FEED THE
// DEMAND WINDOW WITH THE SERVICE JUST RENDERED
void BPF_STRUCT_OPS(panda_stopping, struct task_struct *p,
		    bool runnable)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	tctx->cached_weight = effective_weight(p, tctx);
	tctx->last_cpu = bpf_get_smp_processor_id();
	// STABLE HOME: PIN ONCE TO THE FIRST CPU WE RUN ON; NEVER CHASE last_cpu
	// (REWRITTEN EVERY STOP -> THE MIGRATION-STORM ROOT). RE-HOME ONLY IF THE OLD
	// HOME WENT INVALID (IT WENT OFFLINE, OR THE TASK'S MASK DROPPED IT) SO WE
	// NEVER STRAND THE TASK. THE MASK ALONE DOES NOT SAY: A DEFAULT MASK KEEPS
	// AN OFFLINE CPU.
	if (!seat_ok(tctx->home_cpu) ||
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

	// SERVICE LEDGER: A RUN THAT CONSUMED A FULL TARGET ADVANCES THE COUNT, ANY
	// SHORTER RUN CLEARS IT. SATURATES SO A LONG HOG CANNOT BANK UNBOUNDED CREDIT.
	if (svc >= codel_target_ns) {
		if (tctx->standing_runs < STANDING_CAP)
			tctx->standing_runs += 1;
	} else {
		tctx->standing_runs = 0;
	}

	// THE RUN HABIT. THE SAMPLE IS THIS RUN'S SERVICE, CLAMPED TO FOUR LIVE
	// TARGETS SO ONE LATE PREEMPT CANNOT PULL THE AVERAGE OUTSIDE THE RANGE
	// ANY READER USES; A HOG IS A HOG AT ONE TARGET. SEEDED ON THE FIRST
	// SAMPLE, THEN avg += (sample - avg) / 8 WITH A SIGNED SHIFT, NO DIVIDE.
	// THE BUCKET COUNT IS THE DISTRIBUTION THE PRICE IS READ AGAINST.
	{
		u64 cap = codel_target_ns * EWMA_SAMPLE_CAP_TARGETS;
		u64 sample = svc > cap ? cap : svc;
		u64 avg = tctx->avg_run_ns;
		if (!avg) {
			avg = sample;
		} else {
			s64 d = (s64)sample - (s64)avg;
			avg = (u64)((s64)avg + (d >> EWMA_SHIFT));
		}
		tctx->avg_run_ns = avg;
		struct panda_stats *s = get_stats();
		if (s)
			s->ewma_hist[ewma_bucket(avg) & (EWMA_HIST_BUCKETS - 1)] += 1;
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
void BPF_STRUCT_OPS(panda_tick, struct task_struct *p)
{
	struct panda_stats *s = get_stats();
	struct tuning_knobs *knobs = get_knobs();

	// TAU-SCALING: RE-DERIVE THE TIMING STATICS IF THE LOADER WROTE A NEW
	// TOPOLOGY, AT INITIAL DETECT OR ON HOTPLUG. NOT GATED TO CPU 0 --
	// A CPU-0 GATE LEAVES EVERY tau-DERIVED STATIC AT ITS 12C FALLBACK UNTIL THE
	// FIRST CPU-0 TICK. IDEMPOTENT UNDER NO CHANGE, AND THE CAS ON THE APPLIED
	// GENERATION MAKES CONCURRENT CALLS SAFE: THE FIRST CALL WINS, THE REST
	// SHORT-CIRCUIT ON A SINGLE COMPARE.
	apply_tau_scaling();

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
			// A CPU WENT OFFLINE (SUSPEND TAKES THEM ONE BY ONE): THE
			// RESCUES COUNTED ACROSS IT ARE NOT THIS TICK'S FORCING, AND
			// THE VELOCITY THEY BUILT IS DROPPED WITH THEM. THE COUNT ITSELF
			// IS LEFT ALONE; ONLY THIS TICK'S VIEW OF IT MOVES.
			if (osc_reset_req) {
				osc_reset_req = false;
				prev_rescue_snapshot = cur;
				oscillator_velocity_ns = 0;
			}
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
				// THE DETECTOR FIRED: FULL RECOMPUTE THIS SAME TICK,
				// BEFORE ANY DISPATCH PRICES AGAINST THE TARGET AGAIN --
				// NEVER "RESUME CADENCE AND WAIT ONE PERIOD".
				// REFRACTORY DWELL: RE-PRIME THE RESERVOIR ABOVE
				// RELEASE SO CONTRACTION RESTARTS FROM SCRATCH AND
				// A BURST CANNOT IMMEDIATELY RE-PARK.
				osc_env_unpark();   // the one un-park site
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

	if (s)
		s->codel_target_live = codel_target_ns;

	// THIS CPU'S LANE. A REQUEUE STARVED PAST ITS BOUND BEHIND A RESIDENT
	// SELF-PREEMPTS THIS CPU, SO dispatch()'s AGED-LANE SERVE TAKES IT. IT
	// PREEMPTS INTERACTIVE RUNNERS TOO: UNDER A FORK STORM THE CORES RUN A
	// CONVEYOR BELT OF SHORT WORKERS, EACH YIELDING FAST ONLY FOR THE NEXT ONE,
	// SO THE BURIED TASK NEVER GETS IN. A DECLARED RT POLICY ANSWERS TO
	// lag_cap_ns INSTEAD, AND SO DOES A CPU CARRYING A LIVE HANDOFF PAIR, THE
	// TEST dispatch()'s AGED-LANE SERVE HOLDS: KICKED AT THE TARGET, THE CPU'S
	// DISPATCH SERVES ITS LANE AND THE PAIR WAITS A TICK FOR SOME CPU TO STEAL
	// IT (ipc's PIPE PAIR LOST ITS CPU ABOUT EVERY 2.7 ms). THE LANE'S JUDGE
	// PACES THIS TO ONE PREEMPT PER BOUND, AND IS SHOWN THE LANE'S WAIT EVERY
	// TICK, AN EMPTY LANE'S ZERO INCLUDED: THAT IS WHAT CLEARS ITS ACT COUNT
	// ONCE THE LANE HAS DRAINED.
	{
		u32 lcpu = bpf_get_smp_processor_id();
		u32 lslot = cpu_slot(lcpu);
		struct queue_clock *lq = &lane_qclock[lslot];
		u64 lnow = bpf_ktime_get_ns();
		u64 lw = queue_wait(lq, lnow);
		u64 lpw = pair_warm_ns[lslot];
		bool lpair = lpw && lnow >= lpw && lnow - lpw < codel_target_ns;
		u64 net_bound = (lpair || p->policy == SCHED_FIFO ||
				 p->policy == SCHED_RR)
				  ? lag_cap_ns : codel_target_ns;
		if (queue_act(lq, lw, net_bound, net_bound, lnow)) {
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
		// THE WINDOW STARTS AT THE CLOCK'S NUMBER PLUS THIS CPU'S WINDOW'S
		// OFFSET, AS THE SWEEP'S DOES: scan_win_count WINDOWS ROUND THE
		// MACHINE, ONE WHERE THE CLOCK'S ROTATION KEEPS A SEAT OUT NO
		// LONGER THAN lag_cap_ns.
		if (nr_cpu_ids > 0) {
			u32 nr = nr_cpu_ids;
			if (nr <= TICK_SCAN_BUDGET) {
				for (u32 i = 0; i < TICK_SCAN_BUDGET; i++) {
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
				u32 scan_base = (u32)(now2 >> 20) +
					(this_cpu % scan_win_count) * scan_win_stride;
				for (int i = 0; i < TICK_SCAN_BUDGET; i++) {
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
	// THE BAND IS sweep_band_ns, BPF-DERIVED AND ALWAYS LIVE.
	u32 wcpu = bpf_get_smp_processor_id();
	if (wcpu >= MAX_CPUS)
		return;
	u64 wnow = bpf_ktime_get_ns();
	u64 wait_age = queue_wait(&pcpu_qclock[cpu_slot(wcpu)], wnow);
	if (wait_age == 0)
		return;

	// TWO BOUNDS, NEITHER A CLASS. A DECLARED RT POLICY ANSWERS TO THE STARVATION
	// BOUND, lag_cap_ns, 13.3MS AT THE 12C REFERENCE; EVERYTHING ELSE ANSWERS TO
	// THE BAND, sweep_band_ns, THE OSCILLATOR'S FLOOR -- 233US AT 12C.
	// THE SPLIT IS THE AUDIO QUANTUM. codel_target FALLS INSIDE ONE PipeWire
	// PERIOD, SO A UNIFORM BAND PREEMPTS AN RT THREAD MID-BUFFER WHENEVER A
	// WAITER EXISTS. lag_cap FALLS OUTSIDE ONE, SO RT IS STILL FORCED OFF A CPU
	// IT HAS CAMPED ON, JUST NEVER PART-WAY THROUGH A PERIOD.
	// p->policy IS READ DIRECTLY, SO THE TICK NEEDS NO task_ctx LOOKUP.
	u64 band = (p->policy == SCHED_FIFO || p->policy == SCHED_RR)
		 ? lag_cap_ns : sweep_band_ns();
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
void BPF_STRUCT_OPS(panda_enable, struct task_struct *p)
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
s32 BPF_STRUCT_OPS_SLEEPABLE(panda_init)
{
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
	// A SEAT OR A LANE THAT CANNOT BE CREATED FAILS THE LOAD: A TASK SEATED ON
	// A QUEUE THAT DOES NOT EXIST EJECTS THE SCHEDULER LATER, WITH LESS TO SAY.
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++) {
		s32 err = scx_bpf_create_dsq(i, -1);
		if (!err)
			err = scx_bpf_create_dsq(lane_dsq(i), -1);
		if (err)
			return err;
	}

	// THE ONLINE SET AS THE SCHEDULER STARTS; cpu_online() AND cpu_offline()
	// KEEP IT FROM HERE. A CPU THAT MOVES BETWEEN THIS READ AND THE ATTACH
	// MOVES THE KERNEL'S HOTPLUG SEQUENCE, AND THE LOADER'S hotplug_seq HAS
	// THE ATTACH REFUSED AND RETRIED.
	const struct cpumask *online = scx_bpf_get_online_cpumask();
	int oc;
	bpf_for(oc, 0, MAX_CPUS) {
		if ((u32)oc >= nr_cpu_ids)
			break;
		cpu_up[cpu_slot((u32)oc)] = bpf_cpumask_test_cpu(oc, online);
	}
	scx_bpf_put_cpumask(online);

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

	// THE LOADER FILLS THE TABLES AND WRITES topo BEFORE IT ATTACHES, SO THE
	// TOPOLOGY IS NORMALLY ALREADY HERE AND EVERY tau-SCALED STATIC IS DERIVED
	// NOW. AN UNWRITTEN ONE LEAVES THE MIDPOINT FALLBACKS ABOVE IN PLACE UNTIL
	// THE FIRST TICK AFTER IT LANDS.
	apply_tau_scaling();


	return 0;
}

// EXIT: RECORD EXIT INFO FOR USERSPACE
void BPF_STRUCT_OPS(panda_exit, struct scx_exit_info *ei)
{
	UEI_RECORD(uei, ei);
}

// THE DUMP. WHEN THE KERNEL EJECTS THE SCHEDULER IT CALLS dump() ONCE,
// dump_cpu() FOR EVERY CPU AND dump_task() FOR EVERY RUNNABLE TASK, AND
// CARRIES THE TEXT IN THE EXIT INFO BESIDE ITS OWN PER-CPU AND PER-TASK
// LINES. EVERY CLOCK, EVERY SEAT STAMP AND EVERY TASK'S QUEUE IS PRINTED, SO
// A STRAND NAMES THE QUEUE IT SAT ON, THE SEAT THAT HELD IT AND THE RESCUE
// THAT DID NOT REACH IT. AGES ARE IN NS AT THE DUMP's OWN CLOCK.
void BPF_STRUCT_OPS(panda_dump, struct scx_dump_ctx *dctx)
{
	scx_bpf_dump("panda: target=%llu seed=%llu floor=%llu max=%llu lag_cap=%llu tau=%llu eq=%llu\n",
			 codel_target_ns, codel_seed_ns, codel_target_floor_ns,
			 codel_target_max_ns, lag_cap_ns, topo.tau_ns, topo.codel_eq_ns);
	scx_bpf_dump("panda: domains=%u peers=%u rescues=%llu slice=%llu batch=%llu thresh=%llu phi_base=%llu\n",
			 topo.nr_domains, topo.affinity_domain_peers,
			 global_rescue_count, knobs_g.slice_ns,
			 knobs_g.batch_slice_ns, knobs_g.codel_thresh_ns,
			 phi_base_cost_ns);
	scx_bpf_dump("panda: topology generation=%llu applied=%llu\n",
			 topo.generation, last_topo_generation);
}

void BPF_STRUCT_OPS(panda_dump_cpu, struct scx_dump_ctx *dctx, s32 cpu,
		    bool idle)
{
	if (cpu < 0 || (u32)cpu >= nr_cpu_ids)
		return;
	u64 now = bpf_ktime_get_ns();
	u32 slot = cpu_slot((u32)cpu);
	struct queue_clock *q = &pcpu_qclock[slot];
	u64 start = run_start_ns[slot];
	u64 pw = pair_warm_ns[slot];
	scx_bpf_dump("panda: cpu %d idle=%d up=%d dom=%u queued=%d arrivals=%llu departures=%llu wait=%llu sojourn=%llu acts=%llu\n",
		     cpu, idle, cpu_up[slot], cpu_domain_of(cpu),
		     scx_bpf_dsq_nr_queued((u64)cpu), q->arrivals, q->departures,
		     queue_wait(q, now), q->last_sojourn_ns, q->acts);
	struct queue_clock *lq = &lane_qclock[slot];
	scx_bpf_dump("panda: cpu %d lane queued=%d arrivals=%llu departures=%llu wait=%llu sojourn=%llu acts=%llu\n",
			 cpu, scx_bpf_dsq_nr_queued(lane_dsq((u32)cpu)), lq->arrivals,
			 lq->departures, queue_wait(lq, now), lq->last_sojourn_ns, lq->acts);
	scx_bpf_dump("panda: cpu %d ran=%llu expect=%llu pair_warm_age=%llu next_act_in=%lld\n",
		     cpu, now > start ? now - start : 0, run_expect_ns[slot],
		     (pw && now > pw) ? now - pw : 0,
		     (s64)q->next_act - (s64)now);
}

void BPF_STRUCT_OPS(panda_dump_task, struct scx_dump_ctx *dctx,
		    struct task_struct *p)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx) {
		scx_bpf_dump("panda: no task_ctx\n");
		return;
	}
	u64 now = bpf_ktime_get_ns();
	scx_bpf_dump("panda: queued_on=%lld wait=%llu last=%d home=%d habit=%llu standing=%u wake=%d sync=%d fanout=%d path=%u allowed=%d\n",
		     (s64)tctx->queued_on - 1,
		     (tctx->wait_since && now > tctx->wait_since)
			     ? now - tctx->wait_since : 0,
		     tctx->last_cpu, tctx->home_cpu, tctx->avg_run_ns,
		     tctx->standing_runs, !tctx->ran_since_wake, tctx->sync_wake,
		     tctx->fanout_wake, tctx->dispatch_path, p->nr_cpus_allowed);
}

// EXIT_TASK: A DYING TASK LEAVES WHATEVER QUEUE ITS CLOCK STILL HAS IT ON.
// BPF_F_NO_PREALLOC TASK STORAGE FREES task_ctx ITSELF.
void BPF_STRUCT_OPS(panda_exit_task, struct task_struct *p,
		    struct scx_exit_task_args *args)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;
	qclock_depart(tctx, bpf_ktime_get_ns(), false);
}

// QUIESCENT: TASK GOES TO SLEEP. IT LEAVES ITS QUEUE UNRUN AND ITS WAIT ENDS.
void BPF_STRUCT_OPS(panda_quiescent, struct task_struct *p,
		    u64 deq_flags)
{
	struct task_ctx *tctx = lookup_task_ctx(p);
	if (tctx) {
		qclock_depart(tctx, bpf_ktime_get_ns(), false);
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
void BPF_STRUCT_OPS(panda_cpu_release, s32 cpu,
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

// THE LOADER POLLS THE ONLINE SET, RE-DERIVES THE TOPOLOGY OVER IT AND
// PUBLISHES A NEW topo.generation, WHICH apply_tau_scaling() PICKS UP. THESE
// CALLBACKS RUN BEFORE THE LOADER HAS WRITTEN ANYTHING, SO THEY DO NOT ASK FOR
// A RE-DERIVATION: ONE FORCED HERE READ THE OLD TOPOLOGY AND MARKED IT
// APPLIED, AND A NEW TOPOLOGY WITH THE SAME tau WAS THEN NEVER APPLIED.
void BPF_STRUCT_OPS(panda_cpu_online, s32 cpu)
{
	if ((u32)cpu < nr_cpu_ids)
		cpu_up[cpu_slot((u32)cpu)] = true;
}

void BPF_STRUCT_OPS(panda_cpu_offline, s32 cpu)
{
	if ((u32)cpu < nr_cpu_ids)
		cpu_up[cpu_slot((u32)cpu)] = false;

	// THE OSCILLATOR'S FEEDBACK IS STALE ACROSS A SUSPEND. THE CPU-0 TICK OWNS
	// IT, SO THIS ASKS AND THE TICK RESETS.
	osc_reset_req = true;
}

SCX_OPS_DEFINE(panda_ops,
	       .select_cpu   = (void *)panda_select_cpu,
	       .enqueue      = (void *)panda_enqueue,
	       .dispatch     = (void *)panda_dispatch,
	       .runnable     = (void *)panda_runnable,
	       .running      = (void *)panda_running,
	       .stopping     = (void *)panda_stopping,
	       .tick         = (void *)panda_tick,
	       .enable       = (void *)panda_enable,
	       .quiescent    = (void *)panda_quiescent,
	       .cpu_release  = (void *)panda_cpu_release,
	       .cpu_online   = (void *)panda_cpu_online,
	       .cpu_offline  = (void *)panda_cpu_offline,
	       .init         = (void *)panda_init,
	       .exit_task    = (void *)panda_exit_task,
	       .exit         = (void *)panda_exit,
	       .dump         = (void *)panda_dump,
	       .dump_cpu     = (void *)panda_dump_cpu,
	       .dump_task    = (void *)panda_dump_task,
	       .exit_dump_len = 262144,
	       .flags        = SCX_OPS_BUILTIN_IDLE_PER_NODE |
			       SCX_OPS_KEEP_BUILTIN_IDLE |
			       SCX_OPS_ALLOW_QUEUED_WAKEUP,
	       .timeout_ms   = 10000,
	       .name         = "scx_panda");