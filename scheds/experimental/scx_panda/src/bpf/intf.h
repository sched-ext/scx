// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// scx_panda SHARED INTERFACE
// CONSTANTS AND STRUCTURES SHARED BETWEEN BPF AND THE LOADER

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

// BPF VERIFIER LOOP BOUNDS AND MAP CEILINGS. THE LOADER RESIZES THE TOPOLOGY
// TABLES TO THE BOX BEFORE LOAD; THESE ARE THE MOST IT MAY ASK FOR.
#define MAX_CPUS  1024
#define MAX_NODES 32
// OVERFLOW-DOMAIN CEILING. DSQs ARE PRE-ALLOCATED AT INIT;
// topo.nr_overflow_domains GATES WHICH ARE LIVE.
#define MAX_OVERFLOW_DOMAINS 32
// PER-CPU affinity_rank SLOT COUNT: MAX_CPUS >> 3 = 128 AT MAX_CPUS=1024.
// SLOTS PAST nr_cpu_ids - 1 HOLD (u32)-1; LOOPS EARLY-EXIT ON THE SENTINEL.
#define MAX_AFFINITY_CANDIDATES (MAX_CPUS >> 3)

// KERNEL PROCESS FLAGS (NOT IN vmlinux.h -- THESE ARE #define MACROS)
#define PF_KTHREAD 0x00200000

// THE KNOB SET. BPF-OWNED: DERIVED FROM tau IN apply_tau_scaling() AND READ BY
// task_slice(), running(), dispatch() AND tick(). NO USERSPACE WRITER.
struct tuning_knobs {
	u64 slice_ns;           // BASE TIME SLICE
	u64 batch_slice_ns;     // STANDING TASK SLICE CEILING
	u64 codel_thresh_ns;    // tick() PER-CPU SOJOURN SCAN THRESHOLD
	u64 burst_slice_ns;     // SLICE CEILING DURING LONGRUN
};

// PER-CPU STATISTICS (BPF_MAP_TYPE_PERCPU_ARRAY VALUE). THE LOADER READS AND
// FOLDS THEM FOR ITS PRINTER; NOTHING ACTUATES ON THEM.
struct panda_stats {
	u64 nr_dispatches;      // TOTAL TASKS DISPATCHED (ALL PATHS)
	u64 nr_idle_hits;       // SELECT_CPU FAST PATH SEATS
	u64 nr_shared;          // ENQUEUE SEATS, EVERY TIER
	u64 nr_preempt;         // TICK PREEMPTIONS
	u64 wake_lat_sum;       // SUM WAKEUP->RUN LATENCY (NS)
	u64 wake_lat_samples;   // COUNT OF WAKEUP LATENCY SAMPLES
	u64 nr_keep_running;    // prev KEPT WHEN NOTHING WAS QUEUED
	u64 nr_hard_kicks;      // ENQUEUE: SCX_KICK_PREEMPT ISSUED
	u64 nr_soft_kicks;      // ENQUEUE: SCX_KICK_IDLE OR FLAG 0 ISSUED
	u64 nr_enq_wakeup;      // ENQUEUE: TASK JUST WOKE UP (!ran_since_wake)
	u64 nr_enq_requeue;     // ENQUEUE: TASK RE-ENQUEUED (ran_since_wake)
	u64 wake_lat_idle_sum;  // LATENCY SUM: IDLE FAST PATH (NS)
	u64 wake_lat_idle_cnt;  // LATENCY COUNT: IDLE FAST PATH
	u64 wake_lat_kick_sum;  // LATENCY SUM: KICKED ENQUEUE (NS)
	u64 wake_lat_kick_cnt;  // LATENCY COUNT: KICKED ENQUEUE
	// L2 CACHE AFFINITY, COUNTED IN select_cpu() IDLE PATH AND enqueue() TIER 1.
	// TWO LANES KEYED ON PF_WQ_WORKER: interactive IS THE KWORKER LANE.
	u64 nr_l2_hit_batch;
	u64 nr_l2_miss_batch;
	u64 nr_l2_hit_interactive;
	u64 nr_l2_miss_interactive;
	u64 batch_sojourn_ns;   // CURRENT OVERFLOW WAIT AGE (NS), WRITTEN BY tick()
	u64 longrun_mode_active;// 1 IF SUSTAINED OVERFLOW PRESSURE, WRITTEN BY tick()
	u64 nr_overflow_rescue; // DISPATCHES BY try_service_aged_overflow AT
	                        // codel_target_ns
	// CROSS-DOMAIN LANDINGS BY PLACEMENT PATH, INDEXED BY XDOM_* BELOW.
	u64 nr_cross_domain[8];
	u64 nr_osc_park;        // OSCILLATOR ENVELOPE PARK ENTRIES (CPU-0 TICK)
	u64 nr_spill_kick_preempt; // select_cpu SEATS REDIRECTED OFF AN IDLE PICK
	                        // ONTO A BUSY SPILL CPU, KICKED SCX_KICK_PREEMPT
	u64 nr_steal;           // EVERY SUCCESSFUL STEP 1 PEER move_to_local
	u64 nr_kick_declined;   // requeue_kick_flag RETURNING KICK_NONE,
	                        // SELF-TARGETED ONLY. NO KFUNC WAS CALLED
	// THE RUN HABIT'S PRICE AT THE SEAT. used: THE RESIDENT RAN INSIDE ITS HABIT
	// AND WHAT IT HAD LEFT OF IT BOUNDED THE SEAT'S WAIT. overrun: THE RESIDENT
	// WAS PAST ITS HABIT AND THE GRANTED SLICE STOOD. THE REFUSAL COUNTER THE
	// PRICE WAS BORN WITH.
	u64 nr_seat_expect_used;
	u64 nr_seat_expect_overrun;
	// THE RUN HABIT'S DISTRIBUTION: ONE INCREMENT PER stopping() IN THE
	// BUCKET floor(log2(avg_run_ns / 1us)), 0 UNDER 2us, 15 FROM 32ms.
	u64 ewma_hist[16];
	u64 codel_target_live;   // THE LIVE TARGET, WRITTEN BY CPU 0's TICK; THE BAND EVERY RUN RAN AT
};

// XDOM PATH INDICES FOR panda_stats.nr_cross_domain[]. POSITIONAL IN THE
// PRINTER'S OUTPUT: NEVER RENUMBER.
#define XDOM_SEL_TIGHT   0   // select_cpu sync pipe-partner co-location
#define XDOM_SEL_SYNC    1   // select_cpu WAKE_SYNC phi_warm_target
#define XDOM_SEL_NORMAL  2   // select_cpu normal_path phi_warm_target
#define XDOM_SEL_DFL     3   // select_cpu scx_bpf_select_cpu_dfl idle pick
#define XDOM_ENQ_T1      4   // enqueue TIER 1 idle (pick_idle_cpu_node)
#define XDOM_ENQ_T2      5   // enqueue TIER 2 warm-anchor spill
#define XDOM_STEAL       6   // dispatch STEP 1 R_eff steal (this_cpu vs peer)
#define XDOM_STEP5       7   // dispatch STEP 5 cross-domain work-conservation

#endif // __INTF_H
