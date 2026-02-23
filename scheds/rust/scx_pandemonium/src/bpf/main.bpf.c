// PANDEMONIUM -- SCHED_EXT KERNEL SCHEDULER
// ADAPTIVE DESKTOP SCHEDULING FOR LINUX
//
// BPF: BEHAVIORAL CLASSIFICATION + MULTI-TIER DISPATCH
// RUST: ADAPTIVE CONTROL LOOP + REAL-TIME TELEMETRY
//
// ARCHITECTURE:
//   SELECT_CPU IDLE FAST PATH -> PER-CPU DSQ (ZERO CONTENTION)
//   ENQUEUE IDLE FOUND -> PER-CPU DSQ DIRECT PLACEMENT (ZERO CONTENTION)
//   ENQUEUE INTERACTIVE PREEMPT -> PER-CPU DSQ + HARD KICK
//   ENQUEUE FALLBACK -> PER-NODE OVERFLOW DSQ (VTIME-ORDERED)
//   DISPATCH -> PER-CPU DSQ, NODE OVERFLOW, CROSS-NODE STEAL, KEEP_RUNNING
//   TICK + GUARD -> EVENT-DRIVEN BATCH PREEMPTION (ZERO POLLING)
//
// BEHAVIORAL CLASSIFICATION (FROM v0.9.4):
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

#define TIER_BATCH        0
#define TIER_INTERACTIVE  1
#define TIER_LAT_CRITICAL 2

#define LAT_CRI_THRESH_HIGH  32
#define LAT_CRI_THRESH_LOW   8
#define LAT_CRI_CAP          255

#define WEIGHT_LAT_CRITICAL  256   // 2X
#define WEIGHT_INTERACTIVE   192   // 1.5X
#define WEIGHT_BATCH         128   // 1X

#define EWMA_AGE_MATURE      8
#define EWMA_AGE_CAP         16
#define MAX_WAKEUP_FREQ      64
#define MAX_CSW_RATE         512
#define LAG_CAP_NS           (40ULL * 1000000ULL)

#define SLICE_MIN_NS 100000     // 100US FLOOR


// GLOBALS

static u32 nr_nodes;
static u64 vtime_now;
static u64 preempt_thresh = 10;

// TICK-BASED INTERACTIVE PREEMPTION SIGNAL
// SET BY enqueue() WHEN NON-BATCH TASK HITS OVERFLOW DSQ.
// CLEARED BY tick() AFTER PREEMPTING A BATCH TASK.
static bool interactive_waiting;

// INTERACTIVE GUARDRAIL: TIME-BASED BATCH SLICE CLAMP
// SET IN enqueue() WHEN NON-BATCH TASK HITS OVERFLOW DSQ.
// CHECKED IN task_slice() TO CLAMP BATCH SLICES DURING GUARD WINDOW.
static u64 guard_until_ns;

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

static __always_inline s32 find_idle_l2_sibling(const struct task_ctx *tctx)
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
		if (scx_bpf_test_and_clear_cpu_idle(cpu))
			return cpu;
	}
	return -1;
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
	char key[16];
	__builtin_memcpy(key, p->comm, 16);
	return bpf_map_lookup_elem(&compositor_map, key) != NULL;
}

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

// DEADLINE = DSQ_VTIME + AWAKE_VTIME
// PER-TASK LAG SCALING: INTERACTIVE TASKS GET MORE VTIME CREDIT
// QUEUE-PRESSURE SCALING: CREDIT SHRINKS WHEN DSQ IS DEEP
// TIER-BASED AWAKE CAP: PREVENTS BOOST EXPLOITATION
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
	u64 vtime_floor = vtime_now - LAG_CAP_NS * lag_scale;
	if (time_before(p->scx.dsq_vtime, vtime_floor))
		p->scx.dsq_vtime = vtime_floor;

	// TIER-BASED AWAKE CAP
	u64 awake_cap;
	if (tctx->tier == TIER_LAT_CRITICAL)
		awake_cap = 20ULL * 1000000ULL;
	else if (tctx->tier == TIER_INTERACTIVE)
		awake_cap = 30ULL * 1000000ULL;
	else
		awake_cap = LAG_CAP_NS;

	if (tctx->awake_vtime > awake_cap)
		tctx->awake_vtime = awake_cap;

	return p->scx.dsq_vtime + tctx->awake_vtime;
}

// PER-TIER DYNAMIC SLICING
// LAT_CRITICAL: 1.5X AVG_RUNTIME (TIGHT -- FAST PREEMPTION)
// INTERACTIVE:  2X AVG_RUNTIME (RESPONSIVE)
// BATCH:        KNOB BASE SLICE (CONTROLLED BY ADAPTIVE LAYER)
static __always_inline u64 task_slice(const struct task_ctx *tctx,
				      const struct tuning_knobs *knobs)
{
	u64 base_slice = knobs ? knobs->slice_ns : 1000000;
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
	// GUARD WINDOW: CLAMP DURING INTERACTIVE CONTENTION.
	u64 batch_ceil = knobs ? knobs->batch_slice_ns : 20000000;
	if (batch_ceil < SLICE_MIN_NS)
		batch_ceil = SLICE_MIN_NS;

	base = batch_ceil * tctx->cached_weight >> 7;
	if (base > batch_ceil)
		base = batch_ceil;
	if (base < SLICE_MIN_NS)
		base = SLICE_MIN_NS;

	if (bpf_ktime_get_ns() < guard_until_ns) {
		u64 guard_slice = SLICE_MIN_NS << 1; // 200US
		if (base > guard_slice) {
			base = guard_slice;
			struct pandemonium_stats *s = get_stats();
			if (s)
				__sync_fetch_and_add(&s->nr_guard_clamps, 1);
		}
	}

	return base;
}

// SCHEDULING CALLBACKS

// SELECT_CPU: FAST-PATH IDLE CPU DISPATCH
// DISPATCHES TO PER-CPU DSQ (NOT SCX_DSQ_LOCAL).
// PER-CPU DSQ IS CONSUMED BY OUR dispatch() CALLBACK. SCX_DSQ_LOCAL
// IS INVISIBLE TO dispatch(), CAUSING 6-7MS LATENCY AT LOW CORE
// COUNTS WHERE BATCH TASKS BLOCK LOCAL TASK PICKUP.
s32 BPF_STRUCT_OPS(pandemonium_select_cpu, struct task_struct *p,
		   s32 prev_cpu, u64 wake_flags)
{
	bool is_idle = false;
	s32 cpu = scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);

	if (is_idle) {
		struct task_ctx *tctx = lookup_task_ctx(p);
		struct tuning_knobs *knobs = get_knobs();
		u64 sl = tctx ? task_slice(tctx, knobs) : 1000000;

		// PER-CPU DSQ: CONSUMED BY dispatch() CALLBACK.
		// ON AN IDLE CPU THE PER-CPU DSQ IS EMPTY, SO THIS TASK
		// IS THE ONLY ENTRY AND GETS PICKED UP IMMEDIATELY.
		s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
		if (node < 0 || (u32)node >= nr_nodes) node = 0;
		u64 node_dsq = nr_cpu_ids + (u64)node;
		u64 dl = tctx ? task_deadline(p, tctx, node_dsq, knobs)
			      : vtime_now;
		scx_bpf_dsq_insert_vtime(p, (u64)cpu, sl, dl, 0);

		// KICK: WAKE HALTED IDLE CPU TO PROCESS PER-CPU DSQ.
		// SCX_KICK_IDLE FOR ALL: CPU IS ALREADY BEING WOKEN BY THE
		// SCHEDULER (select_cpu_dfl FOUND IT IDLE). PREEMPT IPI IS
		// REDUNDANT -- IDLE CPUS HAVE NOTHING TO PREEMPT.
		scx_bpf_kick_cpu(cpu, SCX_KICK_IDLE);

		if (tctx)
			tctx->dispatch_path = 0;

		struct pandemonium_stats *s = get_stats();
		if (s) {
			s->nr_idle_hits += 1;
			s->nr_dispatches += 1;
			if (tctx)
				count_l2_affinity(s, tctx, cpu);
		}
	}

	return cpu;
}

// ENQUEUE: THREE-TIER PLACEMENT WITH BEHAVIORAL PREEMPTION
// TIER 1: IDLE CPU ON NODE -> DIRECT PER-CPU DSQ (ZERO CONTENTION)
// TIER 2: INTERACTIVE/LAT_CRITICAL -> DIRECT PER-CPU DSQ + HARD PREEMPT
// TIER 3: FALLBACK -> NODE OVERFLOW DSQ + SELECTIVE KICK
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

	// TIER 1: IDLE CPU -> DIRECT PER-CPU DSQ
	// L2 PLACEMENT: TRY IDLE SIBLING IN SAME L2 DOMAIN FIRST.
	// LAT_CRITICAL AND KERNEL THREADS SKIP AFFINITY -- FASTEST CPU WINS.
	// KWORKERS/KSOFTIRQD ARE INFRASTRUCTURE; NEVER L2-STEER THEM.
	// GUARD: CPU MUST BE < nr_cpu_ids SO ITS PER-CPU DSQ EXISTS.
	s32 cpu = -1;
	if (knobs && knobs->affinity_mode > 0 && tctx &&
	    tctx->tier != TIER_LAT_CRITICAL &&
	    !(p->flags & PF_KTHREAD)) {
		cpu = find_idle_l2_sibling(tctx);
	}
	if (cpu < 0)
		cpu = __COMPAT_scx_bpf_pick_idle_cpu_node(p->cpus_ptr, node, 0);
	if (cpu >= 0 && (u64)cpu < nr_cpu_ids) {
		dl = tctx ? task_deadline(p, tctx, node_dsq, knobs)
			  : vtime_now;
		scx_bpf_dsq_insert_vtime(p, (u64)cpu, sl, dl, enq_flags);

		// NON-BATCH: USE PREEMPT KICK TO GUARANTEE IMMEDIATE PICKUP.
		// SCX_KICK_IDLE IS A NO-OP ON BUSY CPUs -- IF THE "IDLE" CPU
		// BECAME BUSY BETWEEN pick_idle AND kick, THE TASK SITS IN
		// THE PER-CPU DSQ FOR UP TO batch_slice_ns (20MS). PREEMPT
		// SENDS AN IPI THAT FORCES IMMEDIATE RESCHEDULE.
		// BATCH TASKS CAN WAIT -- THEY'RE NOT LATENCY-SENSITIVE.
		u64 kick_flag = (tctx && tctx->tier != TIER_BATCH)
			      ? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
		scx_bpf_kick_cpu(cpu, kick_flag);

		if (tctx)
			tctx->dispatch_path = 0;

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
		return;
	}

	// TIER 2: INTERACTIVE PREEMPTION -- PER-CPU DSQ + SELECTIVE KICK
	// LAT_CRITICAL ALWAYS GETS PREEMPTION (WAKEUP OR REQUEUE).
	// INTERACTIVE ONLY ON WAKEUP: REQUEUED INTERACTIVE TASKS WERE JUST
	// RUNNING AND CAN WAIT FOR dispatch() OR tick() (1-4MS WORST).
	// SKIPPING pick_any_cpu_node() + cpu_curr() FOR REQUEUED INTERACTIVE
	// SAVES ~2 BPF HELPER CALLS PER REQUEUE AT HIGH DISPATCH RATES.
	// ONLINE GUARD: pick_any_cpu_node() CAN RETURN OFFLINE CPUs DURING
	// HOTPLUG. OFFLINE CPUs HAVE NO CURRENT TASK (cpu_curr == NULL).
	// IF OFFLINE, FALL THROUGH TO TIER 3 (OVERFLOW DSQ + TICK RESCUE).
	// KICK POLICY: WAKEUPS GET SCX_KICK_PREEMPT (IMMEDIATE IPI FOR
	// INTERACTIVE RESPONSIVENESS). REQUEUES GET SCX_KICK_IDLE (NO IPI
	// ON BUSY CPUs).
	if (tctx &&
	    (tctx->tier == TIER_LAT_CRITICAL ||
	     (is_wakeup && tctx->tier == TIER_INTERACTIVE &&
	      (tctx->wakeup_freq > preempt_thresh ||
	       tctx->avg_runtime < (knobs ? knobs->slice_ns : 1000000))))) {
		cpu = __COMPAT_scx_bpf_pick_any_cpu_node(
			p->cpus_ptr, node, 0);
		if (cpu >= 0 && (u64)cpu < nr_cpu_ids &&
		    __COMPAT_scx_bpf_cpu_curr(cpu)) {
			dl = task_deadline(p, tctx, node_dsq, knobs);
			scx_bpf_dsq_insert_vtime(p, (u64)cpu, sl, dl,
						  enq_flags);
			u64 kick_flag = is_wakeup
				      ? SCX_KICK_PREEMPT : SCX_KICK_IDLE;
			scx_bpf_kick_cpu(cpu, kick_flag);
			tctx->dispatch_path = 1;

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
			return;
		}
	}

	// TIER 3: NODE OVERFLOW DSQ + SELECTIVE KICK
	dl = tctx ? task_deadline(p, tctx, node_dsq, knobs) : vtime_now;
	scx_bpf_dsq_insert_vtime(p, node_dsq, sl, dl, enq_flags);

	// ARM TICK SAFETY NET + INTERACTIVE GUARDRAIL
	// 2MS GUARD: WIDER WINDOW COMPENSATES FOR TIMER ELIMINATION (v2.1.0).
	// CLAMPS BATCH SLICES TO 200US WHILE INTERACTIVE TASKS WAIT IN OVERFLOW.
	if (tctx && tctx->tier != TIER_BATCH) {
		interactive_waiting = true;
		guard_until_ns = bpf_ktime_get_ns() + 2000000; // 2MS GUARD WINDOW
	}

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
		// DSQ DEPTH: CONTENTION SIGNAL FOR RUST ADAPTIVE LAYER
		u64 nr_queued = scx_bpf_dsq_nr_queued(node_dsq);
		s->dsq_depth_sum += nr_queued;
		s->dsq_depth_samples += 1;
	}
}

// DISPATCH: CPU IS IDLE AND NEEDS WORK
// 1. ANTI-STARVATION: OVERFLOW FIRST EVERY 4TH DISPATCH (WHEN QUEUED)
// 2. OWN PER-CPU DSQ (DIRECT PLACEMENT FROM ENQUEUE -- ZERO CONTENTION)
// 3. NODE OVERFLOW DSQ (VTIME-ORDERED, RESPECTS BEHAVIORAL PRIORITY)
// 4. CROSS-NODE STEAL (LAST RESORT)
// 5. KEEP_RUNNING IF PREV STILL WANTS CPU AND NOTHING QUEUED
void BPF_STRUCT_OPS(pandemonium_dispatch, s32 cpu, struct task_struct *prev)
{
	s32 node = __COMPAT_scx_bpf_cpu_node(cpu);
	if (node < 0 || (u32)node >= nr_nodes) node = 0;
	u64 node_dsq = nr_cpu_ids + (u64)node;
	struct pandemonium_stats *s;

	// ANTI-STARVATION: PERIODICALLY DRAIN OVERFLOW BEFORE PER-CPU DSQ.
	// WITHOUT THIS, BATCH TASKS IN THE OVERFLOW DSQ STARVE INDEFINITELY
	// WHEN select_cpu AND enqueue TIER 1/2 CONTINUOUSLY FEED PER-CPU DSQs.
	// EVERY 4TH DISPATCH (PER-CPU COUNTER, NO ATOMICS NEEDED): CHECK
	// OVERFLOW FIRST. PRESERVES LOCALITY 75% OF THE TIME.
	s = get_stats();
	if (s && scx_bpf_dsq_nr_queued(node_dsq) > 0 &&
	    (s->nr_dispatches & 3) == 0) {
		if (scx_bpf_dsq_move_to_local(node_dsq)) {
			s->nr_dispatches += 1;
			return;
		}
	}

	// PER-CPU DSQ: DIRECT PLACEMENT FROM ENQUEUE
	if (scx_bpf_dsq_move_to_local((u64)cpu)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// NODE OVERFLOW DSQ: VTIME-ORDERED CONSUME
	if (scx_bpf_dsq_move_to_local(node_dsq)) {
		s = get_stats();
		if (s)
			s->nr_dispatches += 1;
		return;
	}

	// CROSS-NODE STEAL
	for (u32 n = 0; n < nr_nodes && n < MAX_NODES; n++) {
		if (n != (u32)node &&
		    scx_bpf_dsq_move_to_local(nr_cpu_ids + (u64)n)) {
			s = get_stats();
			if (s)
				s->nr_dispatches += 1;
			return;
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

	tctx->tier = new_tier;
}

// RUNNING: TASK STARTS EXECUTING -- ADVANCE VTIME, RECORD WAKE LATENCY
void BPF_STRUCT_OPS(pandemonium_running, struct task_struct *p)
{
	if (time_before(vtime_now, p->scx.dsq_vtime))
		vtime_now = p->scx.dsq_vtime;

	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx) {
		struct tuning_knobs *knobs = get_knobs();
		p->scx.slice = knobs ? knobs->slice_ns : 1000000;
		return;
	}

	u64 now = bpf_ktime_get_ns();
	tctx->last_run_at = now;

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
			if (wake_lat > s->wake_lat_max)
				s->wake_lat_max = wake_lat;

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
			__sync_fetch_and_add(hist_val, 1);

		if (sleep_dur > 0) {
			u32 sbucket = sleep_bucket(sleep_dur);
			u64 *sval = bpf_map_lookup_elem(&sleep_hist, &sbucket);
			if (sval)
				__sync_fetch_and_add(sval, 1);
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

// TICK: EVENT-DRIVEN BATCH PREEMPTION
// PRIMARY PREEMPTION MECHANISM (BPF TIMER ELIMINATED IN v2.1.0).
// FIRES WHEN interactive_waiting IS SET BY enqueue() TIER 3.
// USES preempt_thresh_ns KNOB FOR REGIME-AWARE THRESHOLD.
void BPF_STRUCT_OPS(pandemonium_tick, struct task_struct *p)
{
	if (!interactive_waiting)
		return;

	struct task_ctx *tctx = lookup_task_ctx(p);
	if (!tctx)
		return;

	struct tuning_knobs *knobs = get_knobs();
	u64 thresh = knobs ? knobs->preempt_thresh_ns : 1000000;

	if (tctx->tier == TIER_BATCH && tctx->avg_runtime >= thresh) {
		scx_bpf_kick_cpu(scx_bpf_task_cpu(p), SCX_KICK_PREEMPT);
		interactive_waiting = false;
		struct pandemonium_stats *s = get_stats();
		if (s)
			__sync_fetch_and_add(&s->nr_preempt, 1);
	}
}

// ENABLE: NEW TASK ENTERS SCHED_EXT
void BPF_STRUCT_OPS(pandemonium_enable, struct task_struct *p)
{
	p->scx.dsq_vtime = vtime_now;

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
			struct pandemonium_stats *s = get_stats();
			if (s)
				s->nr_procdb_hits += 1;
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

	// CREATE PER-CPU DSQs (DSQ ID = CPU ID, 0..nr_cpu_ids-1)
	for (u32 i = 0; i < nr_cpu_ids && i < MAX_CPUS; i++)
		scx_bpf_create_dsq(i, -1);

	// CREATE PER-NODE OVERFLOW DSQs (DSQ ID = nr_cpu_ids + NODE ID)
	for (u32 i = 0; i < nr_nodes && i < MAX_NODES; i++)
		scx_bpf_create_dsq(nr_cpu_ids + i, (s32)i);

	// CORE-COUNT-SCALED PREEMPTION THRESHOLD
	preempt_thresh = 60 / (nr_cpu_ids + 2);
	if (preempt_thresh < 3)
		preempt_thresh = 3;
	if (preempt_thresh > 20)
		preempt_thresh = 20;

	// INITIALIZE DEFAULT TUNING KNOBS
	struct tuning_knobs *knobs = bpf_map_lookup_elem(&tuning_knobs_map, &zero);
	if (knobs) {
		knobs->slice_ns = 1000000;
		knobs->preempt_thresh_ns = 1000000;
		knobs->lag_scale = 4;
		knobs->batch_slice_ns = 20000000;        // 20MS FLAT DEFAULT
		knobs->cpu_bound_thresh_ns = 2500000;    // 2.5MS (RESERVED FOR FUTURE USE)
		knobs->lat_cri_thresh_high = LAT_CRI_THRESH_HIGH; // 32
		knobs->lat_cri_thresh_low  = LAT_CRI_THRESH_LOW;  // 8
		knobs->affinity_mode = 0;                // OFF BY DEFAULT (RUST SETS PER REGIME)
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

// CPU RELEASE: RESCUE STRANDED TASKS WHEN RT/DL PREEMPTS OUR CPU
// CALLED WHEN THE KERNEL TAKES A CPU AWAY FROM SCHED_EXT (DL SERVER,
// RT TASKS, PIPEWIRE). WITHOUT THIS, TASKS THAT dispatch() MOVED TO THE
// LOCAL DSQ VIA scx_bpf_dsq_move_to_local() GET STUCK, TRIGGERING THE
// WATCHDOG. EVERY REFERENCE SCHEDULER IMPLEMENTS THIS.
void BPF_STRUCT_OPS(pandemonium_cpu_release, s32 cpu,
		    struct scx_cpu_release_args *args)
{
	u32 nr = scx_bpf_reenqueue_local();
	if (nr > 0) {
		struct pandemonium_stats *s = get_stats();
		if (s)
			s->nr_reenqueue += nr;
	}
}

// CPU HOTPLUG CALLBACKS
void BPF_STRUCT_OPS(pandemonium_cpu_online, s32 cpu) {}
void BPF_STRUCT_OPS(pandemonium_cpu_offline, s32 cpu) {}

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