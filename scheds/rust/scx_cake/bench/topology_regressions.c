/* Offline policy models, NOT an emulation of kernel races or a timing test. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include "intf.h"
#include "stats.h"
#define __noinline
#define __arg_trusted
#define barrier_var(x) ((void)(x))
#define bpf_for(i, start, end) for ((i) = (start); (i) < (int)(end); (i)++)
#define CAKE_KICK_IDLE 1
#define CAKE_ENQ_WAKEUP 1
#define CAKE_ENQ_REENQ (1ULL << 40)
#define CAKE_ENQ_IMMED immed_flags
static u64 immed_flags = 1ULL << 33;
#define CAKE_DSQ_LOCAL_ON (1ULL << 63)
#define PF_IDLE 2
#define PF_KTHREAD 4
#define CAKE_TASK_QUEUED 1
#define CAKE_PICK_IDLE_CORE 1
#define CAKE_NEIGHBOUR_PROBE_DEPTH 3
#define PREEMPT_PROTECT_SHIFT 4
#define PROBE_PROTECT_SHIFT 2
struct cpumask { u64 bits[1]; };
struct task_struct {
    struct cpumask *cpus_ptr;
    struct { s32 cpu; } thread_info;
    struct { u64 dsq_vtime, flags; } scx;
    struct { u64 sum_exec_runtime; } se;
    u64 nvcsw;
    int pid, nr_cpus_allowed;
    unsigned flags;
};
struct cake_slot { u64 word; };
struct cake_run_slot { u64 seat_pid, stamp, retake, seat_seq; };
struct cake_groove { u16 seat_cpu; u32 seat_pid; u64 seat_seq; };
struct bpf_spin_lock { pthread_mutex_t mutex; };
struct cake_seat_lock { struct bpf_spin_lock lock; };
static struct cake_seat_lock locks[64];
static int cake_seat_locks;
static bool fail_lookup;
enum { CAKE_SEAT_RELEASE, CAKE_SEAT_RUN, CAKE_SEAT_HOLD };
static void *bpf_map_lookup_elem(void *map, u32 *cpu) {
    return fail_lookup || *cpu >= 64 ? NULL : &locks[*cpu];
}
static void bpf_spin_lock(struct bpf_spin_lock *lock) { assert(!pthread_mutex_lock(&lock->mutex)); }
static void bpf_spin_unlock(struct bpf_spin_lock *lock) { assert(!pthread_mutex_unlock(&lock->mutex)); }
static struct {
    struct cake_slot frontier, wake_mark[MAX_LLCS], remote_pool[64];
    struct cake_run_slot run[MAX_CPUS];
    u64 qmask[QMASK_WORDS];
} cake;
static u64 cake_core_free, cake_idle_words[QMASK_WORDS], cake_seat_word, cake_sink_word;
static u64 cpu_irq_hot_words[QMASK_WORDS];
static struct { u32 depth; } cake_irq_live[MAX_CPUS];
static u64 cpu_llc_word[MAX_CPUS], kernel_idle, lives[MAX_CPUS], ran_ns;
static s32 cpu_sibling[MAX_CPUS];
static u32 cake_smt_shift = 64;
static u64 cake_smt_left, cake_smt_right;
static u16 cpu_steal_order[STEAL_SPAN * STEAL_SPAN];
static u32 nr_llcs, nr_cpu_span, nr_steal_cpus;
static u32 cake_rank_tiers;
static u64 cpu_perf_tier[64], cpu_perf_known;
static struct cpumask idle_snapshot, core_snapshot;
static int refs;
static const struct cpumask *scx_bpf_get_idle_cpumask(void) {
    idle_snapshot.bits[0] = kernel_idle; refs++; return &idle_snapshot;
}
static const struct cpumask *scx_bpf_get_idle_smtmask(void) {
    core_snapshot.bits[0] = cake_core_free & kernel_idle; refs++; return &core_snapshot;
}
static void scx_bpf_put_idle_cpumask(const struct cpumask *mask) { assert(refs > 0); refs--; }
static bool cake_one_word, cake_tog_g85, cake_tog_g86, cake_tog_g87;
static bool cake_tog_g89;
static bool cake_tog_probe, steal_order_live, wall_starved;
static u64 cake_handoff_max_ns = 1000;
static struct cpumask affinity;
static struct task_struct task;
static int kicks, last_kick, global_picks, moves, occupant_reads;
static bool pool_present, own_present, refuse_consume;
static void cake_stat_inc(u32 stat) {}
static bool time_before(u64 a, u64 b) { return (s64)(a-b) < 0; }
static bool bpf_cpumask_test_cpu(s32 c, const struct cpumask *m) {
    return c >= 0 && c < 64 && (m->bits[0] & (1ULL << c));
}
static bool cake_taci(s32 c, u32 site) {
    cake_core_free &= ~(1ULL << c);
    if (cpu_sibling[c] >= 0) cake_core_free &= ~(1ULL << cpu_sibling[c]);
    if (!bpf_cpumask_test_cpu(c, &(struct cpumask){{kernel_idle}})) return false;
    kernel_idle &= ~(1ULL << c); return true;
}
static void cake_claim_retire(s32 cpu) {}
static bool cake_cpu_clean(s32 cpu) { return !(cake_sink_word & (1ULL << cpu)); }
static s32 cake_idle_hint_claim(struct task_struct *p) { return -1; }
static s32 cake_pick_idle(const struct cpumask *m, u64 flags) {
    global_picks++;
    u64 w = kernel_idle & m->bits[0];
    if (!w) return -1;
    int c = __builtin_ctzll(w); kernel_idle &= ~(1ULL << c); return c;
}
static s32 cake_pick_idle_escape(struct task_struct *p) { return cake_pick_idle(p->cpus_ptr, 0); }
static u64 cake_cadence_depth(const struct task_struct *p) { return 0; }
static u64 cake_occupant_live(s32 cpu, u64 *ran) { occupant_reads++; *ran = ran_ns; return lives[cpu]; }
static struct task_struct *current_task;
static struct task_struct *cake_cpu_curr(s32 cpu) { return current_task; }
static u64 cake_now(u32 site) { return 10000; }
static u64 cake_burst_ns(const struct task_struct *p) { return p->se.sum_exec_runtime / (p->nvcsw | 1); }
static bool cake_starved(const struct task_struct *p) { return false; }
static void *cake_groove_of(struct task_struct *p) { return NULL; }
static bool cake_producer(void *p) { return false; }
static void cake_kick(s32 cpu, u64 flags) { kicks++; last_kick = cpu; }
static void cake_kick_preempt(s32 cpu) { cake_kick(cpu, 2); }
static void cake_probe_x(u32 site, s32 from, s32 to) {}
static u64 cake_pool_dsq(u32 llc) { return LLC_WAKE_DSQ_BASE + llc; }
static u32 cake_llc_of(s32 cpu) { return nr_llcs > 1 ? (u32)cpu / 4 : 0; }
static u32 cake_nrq(u64 dsq) { return dsq == cake_pool_dsq(0) && pool_present; }
static struct task_struct *cake_dsq_peek(u64 dsq) {
    return ((pool_present && dsq == cake_pool_dsq(0)) ||
            (own_present && dsq == 0)) ? &task : NULL;
}
static bool cake_move_to_local(u64 dsq) { moves++; return !refuse_consume && cake_dsq_peek(dsq) != NULL; }
static bool cake_wake_starved(u32 llc) { return wall_starved; }
static void cake_wake_serve_stamp(u32 llc) {}
static bool cake_qmark_test(u32 c) { return (cake.qmask[c >> 6] >> (c & 63)) & 1; }
static bool cake_cross_llc(s32 a, s32 b) { return (a < 4) != (b < 4); }
static bool cake_probe_steal(u32 a, u32 b) { return true; }
static u64 inserted_dsq, inserted_vtime, inserted_slice, inserted_flags;
static int inserts, wake_routes, pinned_preempts;
static void cake_dsq_insert_vtime(struct task_struct *p, u64 dsq, u64 slice, u64 vt, u64 flags) {
    inserts++; inserted_dsq = dsq; inserted_vtime = vt;
    inserted_slice = slice; inserted_flags = flags; p->scx.dsq_vtime = vt;
    pool_present = dsq == cake_pool_dsq(0); own_present = dsq == 0;
}
static void cake_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags) {
    cake_dsq_insert_vtime(p, dsq, slice, p->scx.dsq_vtime, flags);
}
static u64 cake_task_slice(const struct task_struct *p) { return 50000; }
static bool cake_starved_turn(const struct task_struct *p) { return false; }
static void cake_enqueue_wake(struct task_struct *p, s32 cpu) { wake_routes++; }
static void cake_qmark_set(u32 cpu) { cake.qmask[cpu >> 6] |= 1ULL << (cpu & 63); }
static void cake_pinned_wake_preempt(struct task_struct *p, s32 cpu, u64 depth, u64 slice) {
    pinned_preempts++;
}
#include "functions.h"
static void reset(void) {
    current_task = NULL;
    cake_smt_shift = 64; cake_smt_left = cake_smt_right = 0;
    assert(refs == 0);
    fail_lookup = false; cake_rank_tiers = 0; cpu_perf_known = 0;
    memset(cpu_perf_tier, 0, sizeof(cpu_perf_tier));
    memset(cpu_irq_hot_words, 0, sizeof(cpu_irq_hot_words));
    memset(cake_irq_live, 0, sizeof(cake_irq_live));
    memset(&cake, 0, sizeof(cake)); memset(lives, 0, sizeof(lives));
    memset(cpu_steal_order, 0, sizeof(cpu_steal_order));
    for (int i = 0; i < MAX_CPUS; i++) { cpu_llc_word[i] = 255; cpu_sibling[i] = -1; }
    cake_one_word = cake_tog_g85 = cake_tog_g86 = cake_tog_g87 = cake_tog_g89 = true;
    cake_tog_probe = false;
    steal_order_live = wall_starved = pool_present = own_present = refuse_consume = false;
    nr_llcs = 1; nr_cpu_span = 8; nr_steal_cpus = 7;
    cake_core_free = cake_idle_words[0] = kernel_idle = 255;
    cake_seat_word = cake_sink_word = 0;
    affinity.bits[0] = 255;
    task = (struct task_struct){.cpus_ptr=&affinity, .pid=7, .nr_cpus_allowed=8};
    cake.frontier.word = task.scx.dsq_vtime = 100000000;
    ran_ns = 1000000; kicks = global_picks = moves = occupant_reads = 0; last_kick = -1;
    inserted_dsq = inserted_vtime = inserted_slice = inserted_flags = 0;
    inserts = wake_routes = pinned_preempts = 0;
    immed_flags = 1ULL << 33;
}
static void forced_requeues(void) {
    /* The current enqueue body, followed by the real remote offer consumer:
     * an RT-displaced task must reach CPU4 although CPU0's die is full. */
    reset(); nr_llcs = 2; cpu_llc_word[0] = 15;
    kernel_idle = cake_core_free = 240;
    u64 vt = task.scx.dsq_vtime;
    cake_enqueue(&task, CAKE_ENQ_REENQ);
    assert(inserts == 1 && inserted_dsq == cake_pool_dsq(0));
    assert(inserted_vtime == vt && inserted_slice == 50000);
    assert(inserted_flags == CAKE_ENQ_REENQ && wake_routes == 0);
    assert(cake.qmask[0] == 0 && cake.wake_mark[0].word == 1);
    assert(kicks == 1 && last_kick == 4 && global_picks == 0);
    assert(cake_take_remote(4) && moves == 1);
    puts("PASS: forced continuation requeue publishes the pool and offers an idle remote die without sleeper credit");

    reset(); nr_llcs = 2; cpu_llc_word[0] = 15;
    kernel_idle = cake_core_free = 0xf2;
    cake_enqueue(&task, CAKE_ENQ_REENQ);
    assert(last_kick == 1 && cake.remote_pool[4].word == 0);
    reset(); cake_tog_g85 = cake_tog_g89 = false;
    cake_enqueue(&task, CAKE_ENQ_REENQ);
    assert(inserted_dsq == cake_pool_dsq(0) && kicks == 1);
    reset(); cake_one_word = false; task.thread_info.cpu = 65;
    cake_enqueue(&task, CAKE_ENQ_REENQ);
    assert(inserted_dsq == cake_pool_dsq(0) && kicks == 1);
    puts("PASS: forced requeues prefer local idle service and retain single-pool, wide-host and seat-toggle independence");

    for (int count = 1; count <= 2; count++) {
        reset(); nr_llcs = 2; cpu_llc_word[0] = 15;
        task.nr_cpus_allowed = count; affinity.bits[0] = count == 1 ? 1 : 3;
        kernel_idle = cake_core_free = 240;
        cake_enqueue(&task, CAKE_ENQ_REENQ);
        assert(inserts == 1 && kicks == 0);
        assert(inserted_dsq == (count == 1 ? 0 : cake_pool_dsq(0)));
        assert(cake.qmask[0] == (count == 1 ? 1 : 0));
    }
    reset(); kernel_idle = cake_core_free = 0;
    task.scx.dsq_vtime = 1;
    cake_enqueue(&task, CAKE_ENQ_REENQ);
    assert(inserted_vtime == cake.frontier.word - SLICE_NS && kicks == 0);
    assert(wake_routes == 0 && pinned_preempts == 0);
    puts("PASS: forced requeues respect pinned/local-only affinity and continuation vtime floor with no idle CPU");

    for (int owner = 0; owner <= 1; owner++) {
        reset(); cake.run[0].retake = 1;
        cake.run[0].seat_pid = owner ? task.pid : task.pid + 1;
        cake_enqueue(&task, 0);
        assert(inserted_dsq == (owner ? 0 : cake_pool_dsq(0)));
    }
    reset(); cake_tog_g85 = false; cake.run[0].retake = 1;
    cake_enqueue(&task, 0);
    assert(inserted_dsq == 0 && cake.qmask[0] == 1);
    puts("PASS: ordinary continuations retain owner queues and existing seat-collision routing");
    for (unsigned supported = 0; supported < 2; supported++) {
        reset(); immed_flags = supported ? 1ULL << 33 : 0;
        task.flags = PF_KTHREAD;
        cake_enqueue(&task, CAKE_ENQ_WAKEUP);
        assert(inserted_dsq == CAKE_DSQ_LOCAL_ON);
        assert(inserted_flags == (CAKE_ENQ_WAKEUP | immed_flags));
        reset(); immed_flags = supported ? 1ULL << 33 : 0;
        task.flags = PF_KTHREAD; task.nr_cpus_allowed = 1;
        cake_enqueue(&task, CAKE_ENQ_WAKEUP);
        assert(inserted_flags == CAKE_ENQ_WAKEUP);
        reset(); task.flags = PF_KTHREAD;
        cake_enqueue(&task, CAKE_ENQ_REENQ);
        assert(inserted_dsq == cake_pool_dsq(0) && inserted_flags == CAKE_ENQ_REENQ);
    }
    puts("PASS: only claimed kernel-thread placement requests immediate admission; pinned service and returned pool work keep valid flags");
}
static u64 reference_slice(u64 runtime, u64 age, u64 n) {
    /* Wider arithmetic states the policy independently of its implementation. */
    __uint128_t want = (__uint128_t)(runtime / n) * 2;
    u64 period = age / n;
    u64 cap = (period > SLICE_NS ? SLICE_NS : period) >> PERIOD_SLICE_CAP_SHIFT;
    if (want > cap) want = cap;
    if (want < cake_handoff_max_ns) want = cake_handoff_max_ns;
    return (u64)want;
}
static void pool_direct_claims(void) {
    struct task_struct peer = {.pid=99, .nr_cpus_allowed=8};
    for (unsigned supported = 0; supported < 2; supported++) {
        for (u64 allowed = 1; allowed < 256; allowed++) {
            reset(); immed_flags = supported ? 1ULL << 33 : 0;
            current_task = &peer;
            affinity.bits[0] = allowed;
            /* The kernel owner is always allowed. */
            task.thread_info.cpu = __builtin_ctzll(allowed);
            task.nr_cpus_allowed = __builtin_popcountll(allowed);
            kernel_idle = cake_core_free = allowed & ~(1ULL << task.thread_info.cpu);
            task.scx.dsq_vtime = 1;
            u64 expected_vtime = cake_wake_vtime(&task);
            cake_enqueue(&task, CAKE_ENQ_WAKEUP);
            assert(inserts == 1);
            if (task.nr_cpus_allowed > 1) {
                assert(inserted_dsq & CAKE_DSQ_LOCAL_ON);
                u32 cpu = inserted_dsq & ~CAKE_DSQ_LOCAL_ON;
                assert(allowed & (1ULL << cpu));
                assert(!(kernel_idle & (1ULL << cpu)));
                assert(inserted_flags == (CAKE_ENQ_WAKEUP | immed_flags));
                assert(inserted_vtime == expected_vtime);
                assert(kicks == 0 && cake.qmask[0] == 0 && cake.wake_mark[0].word == 0);
            } else {
                assert(inserted_dsq == (u64)task.thread_info.cpu);
                assert(kicks == 0 && pinned_preempts == 1);
            }
        }
    }
    reset(); current_task = &peer; kernel_idle = cake_core_free = 0;
    cake_enqueue(&task, CAKE_ENQ_WAKEUP);
    assert(inserted_dsq == cake_pool_dsq(0) && inserted_flags == CAKE_ENQ_WAKEUP);
    assert(pool_present && cake.wake_mark[0].word == 0 && kicks == 0);
    reset(); current_task = &peer; nr_llcs = 2; cpu_llc_word[0] = 15;
    kernel_idle = cake_core_free = 240;
    cake_enqueue(&task, CAKE_ENQ_WAKEUP);
    assert(inserted_dsq == cake_pool_dsq(0) && last_kick == 4);
    assert(cake_take_remote(4));
    reset(); current_task = &peer;
    cake_enqueue(&task, CAKE_ENQ_WAKEUP | CAKE_ENQ_REENQ);
    assert(inserted_dsq == cake_pool_dsq(0) && !(inserted_flags & immed_flags));
    assert(kicks == 1);
    reset(); current_task = &peer; cake_one_word = false; task.thread_info.cpu = 65;
    cake_enqueue(&task, CAKE_ENQ_WAKEUP);
    assert(inserted_dsq & CAKE_DSQ_LOCAL_ON);
    assert(inserted_flags & immed_flags);
    puts("PASS: 510 pool-wake affinity/IMMED cases directly serve the claimed CPU; pinned, no-idle, remote-offer, wide and forced-requeue paths retain service");
}
static void slice_arithmetic(void) {
    reset(); cake_handoff_max_ns = 0;
    for (u64 age = 0; age < 128; age++)
        for (u64 run = 0; run <= age; run++)
            for (u64 n = 1; n < 32; n++)
                assert(cake_slice_from_service(run, age, n) == reference_slice(run, age, n));
    const u64 values[] = {0, 1, 2, 3, 4, 5, 1463, 1464, 1465,
        SLICE_NS - 1, SLICE_NS, SLICE_NS + 1,
        (1ULL << 32) - 1, 1ULL << 32, (1ULL << 63) - 1, 1ULL << 63, ~0ULL};
    for (unsigned floor = 0; floor < 2; floor++) {
        cake_handoff_max_ns = floor ? 1464 : 0;
        for (unsigned a = 0; a < sizeof(values)/sizeof(*values); a++)
            for (unsigned r = 0; r < sizeof(values)/sizeof(*values); r++)
                for (unsigned v = 0; v < sizeof(values)/sizeof(*values); v++) {
                    u64 age = values[a], run = values[r], n = values[v] | 1;
                    assert(cake_slice_from_service(run, age, n) == reference_slice(run, age, n));
                }
    }
    u64 state = 1;
    for (unsigned i = 0; i < 200000; i++) {
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        u64 age = state;
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        u64 run = state;
        state = state * 6364136223846793005ULL + 1442695040888963407ULL;
        u64 n = (state >> (i % 64)) | 1;
        assert(cake_slice_from_service(run, age, n) == reference_slice(run, age, n));
    }
    cake_handoff_max_ns = 1000;
    puts("PASS: one-division slice matches the exact policy across exhaustive rounding, floor/cap, u64 boundaries and 200000 random cases");
}
static void placement(void) {
    reset(); cake_seat_word = 1;
    assert(cake_claim_warm(&task, 0) == 1);
    puts("PASS: groove respects another holder's seat while alternatives are idle");
    reset(); cake_seat_word = 255;
    assert(cake_claim_warm(&task, 0) == 0);
    reset(); cake_seat_word = 1; cake.run[0].seat_pid = task.pid;
    assert(cake_claim_warm(&task, 0) == 0);
    puts("PASS: all-seats fallback and holder's own cached seat remain usable");
    reset(); affinity.bits[0] = 0x31; cake_core_free = kernel_idle = cake_idle_words[0] = 0x33;
    cake_seat_word = 1; cpu_sibling[0] = 4; cpu_sibling[4] = 0;
    cpu_sibling[1] = 5; cpu_sibling[5] = 1;
    assert(cake_claim_warm(&task, -1) == 5);
    puts("PASS: worker prefers the allowed unheld whole core over a seat's SMT sibling");
    for (u64 seats = 0; seats < 16; seats++) {
        for (u64 aff = 1; aff < 16; aff++) {
            reset(); cpu_sibling[0] = 2; cpu_sibling[2] = 0;
            cpu_sibling[1] = 3; cpu_sibling[3] = 1;
            cake_seat_word = seats; affinity.bits[0] = aff;
            u64 held = seats | ((seats & 3) << 2) | ((seats & 12) >> 2);
            u64 preferred = aff & ~held;
            s32 got = cake_claim_warm(&task, 0);
            assert(got >= 0 && (aff & (1ULL << got)));
            if (preferred) assert(preferred & (1ULL << got));
        }
    }
    puts("PASS: 240 SMT seat/affinity configurations preserve preference and progress");
}
static void pools(void) {
    reset(); cake_wake_mark_set(0); assert(cake.wake_mark[0].word == 0);
    nr_llcs = 2; cake_tog_g89 = false;
    cake_wake_mark_set(0); assert(cake.wake_mark[0].word == 0);
    cake_tog_g89 = true;
    cake_wake_mark_set(0); assert(cake.wake_mark[0].word == 1);
    cake_wake_mark_retire(0); assert(cake.wake_mark[0].word == 0);
    pool_present = true; cake.wake_mark[0].word = 1;
    cake_wake_mark_retire(0); assert(cake.wake_mark[0].word == 1);
    puts("PASS: foreign pool marks publish/retire/recheck; single-pool and g89-off publication is absent");
    reset(); kernel_idle = cake_idle_words[0] = 0xf0;
    cake_wake_notify(&task, 0, 100000);
    assert(kicks == 1 && last_kick == 4);
    puts("CONTROL: single LLC notifies idle CPU4 for a pool wake owned by CPU0");
    reset(); nr_llcs = 2; steal_order_live = true;
    for (int i = 0; i < 8; i++) cpu_llc_word[i] = i < 4 ? 0x0f : 0xf0;
    cpu_steal_order[0] = 1; cpu_steal_order[1] = 2; cpu_steal_order[2] = 3;
    kernel_idle = cake_idle_words[0] = 0xf0;
    for (int i = 0; i < 4; i++) lives[i] = 99500000;
    cake_wake_notify(&task, 0, 100000);
    assert(kicks == 1 && last_kick == 4 && global_picks == 0);
    pool_present = true; cake.wake_mark[0].word = 1;
    assert(cake_take_remote(4) && moves == 1);
    assert(!cake_take_remote(4));
    moves = 0;
    assert(!cake_llc_pool_rescue(1) && moves == 0);
    wall_starved = true;
    assert(cake_llc_pool_rescue(1));
    assert(kicks == 1);
    puts("PASS: explicit dual-LLC offer consumes a fresh pool head once; ordinary rescue keeps its age gate");
    for (u64 aff = 1; aff < 256; aff++) {
        reset(); nr_llcs = 2; cpu_llc_word[0] = 15;
        kernel_idle = cake_idle_words[0] = 240; affinity.bits[0] = aff;
        bool offered = cake_offer_remote(&task, 0);
        assert(offered == ((aff & 240) != 0));
        if (offered) {
            assert(last_kick >= 4 && (aff & (1ULL << last_kick)));
            /* The old head disappears before the receiver runs. */
            assert(!cake_take_remote((u32)last_kick));
            assert(cake.remote_pool[last_kick].word == 0);
        }
    }
    reset(); nr_llcs = 2; cpu_llc_word[0] = 15;
    kernel_idle = 0; cake_idle_words[0] = 240;
    assert(!cake_offer_remote(&task, 0) && kicks == 0);
    puts("PASS: 255 offer affinities, disappearing heads and stale idle census preserve targeting and retire failed offers");
    for (u32 cpu = 0; cpu < 64; cpu++) {
        reset(); nr_llcs = 2; nr_cpu_span = 64;
        u32 owner = cpu ^ 32;
        u64 bit = 1ULL << cpu;
        cpu_llc_word[owner] = ~bit;
        affinity.bits[0] = kernel_idle = cake_core_free = bit;
        assert(cake_offer_remote(&task, (s32)owner));
        assert(kicks == 1 && last_kick == (s32)cpu);
        assert(!(kernel_idle & bit));
        for (u32 slot = 0; slot < 64; slot++)
            assert(cake.remote_pool[slot].word ==
                   (slot == cpu ? (u64)cake_llc_of((s32)owner) + 1 : 0));
    }
    puts("PASS: all 64 remote targets publish only to the claimed CPU's slot and kick that same CPU");
}
static void frontier(void) {
    const unsigned idxs[] = {20, 39, IDLE_RECIP_INDEX};
    for (unsigned i = 0; i < 3; i++) {
        reset(); u64 used = 1000000;
        u64 charged = (used * recip_weight[idxs[i]]) >> RECIP_SHIFT;
        /* stopping charges, then running publishes this task's vtime. */
        lives[0] = 100500000;
        u64 candidate = cake_frontier_candidate(cake.frontier.word + charged, 1);
        if (time_before(cake.frontier.word, candidate)) cake.frontier.word = candidate;
        assert(occupant_reads == (i == 0 ? 0 : 1));
        task.scx.dsq_vtime = 97000000;
        task.scx.dsq_vtime = cake_wake_vtime(&task);
        lives[0] = 100500000;
        bool preempt = cake_wake_preempt(&task, 0, PREEMPT_PROTECT_SHIFT, 100000);
        assert(preempt);
        printf("frontier: reciprocal-index=%u 1ms-charge=%.3fms wake-key=%.3fms normal-occupant=100.500ms preempt=%d\n",
               idxs[i], charged/1e6, task.scx.dsq_vtime/1e6, preempt);
    }
    reset(); lives[0] = 200000000;
    assert(cake_frontier_candidate(168000000, 1) == 168000000);
    reset(); assert(cake_frontier_candidate(168000000, 1) == 168000000);
    reset(); lives[0] = 90000000;
    u64 next = cake_frontier_candidate(168000000, 1);
    if (time_before(cake.frontier.word, next)) cake.frontier.word = next;
    assert(cake.frontier.word == 100000000);
    puts("PASS: all-low-weight and lone-CPU clocks advance; peer cap cannot rewind the frontier; normal advances avoid peer reads");
    for (u32 span = 1; span <= MAX_CPUS; span *= 2) {
        reset(); nr_cpu_span = span;
        assert(cake_frontier_candidate(101000000, 0) == 101000000);
        assert(occupant_reads == 0);
        lives[span - 1] = 101000000;
        assert(cake_frontier_candidate(168000000, 0) ==
               (span == 1 ? 168000000 : 101000000));
        assert(occupant_reads == (int)span - 1);
    }
    puts("PASS: frontier spans 1..MAX_CPUS preserve ordinary fast return, self exclusion and last-peer service");
}
static void ring(void) {
    reset(); nr_llcs = 2; steal_order_live = true; own_present = true; cake.qmask[0] = 1;
    cpu_steal_order[4 * STEAL_SPAN] = 0;
    assert(!cake_ring_steal(4) && moves == 0);
    steal_order_live = false;
    assert(cake_ring_steal(4));
    puts("CONFIRMED: matrix ring refuses fresh cross-LLC head; generic ring consumes the same head without the locality gate");
    reset(); nr_llcs = 2; nr_cpu_span = 128; steal_order_live = true;
    own_present = refuse_consume = true; cake.qmask[0] = 1; nr_steal_cpus = 3;
    affinity.bits[0] = 1; /* CPU1 cannot consume CPU0's pinned task. */
    cpu_steal_order[STEAL_SPAN] = 0;
    cpu_steal_order[STEAL_SPAN + 1] = 4;
    cpu_steal_order[STEAL_SPAN + 2] = 5;
    assert(!cake_ring_steal(1) && moves == 1);
    puts("PASS: sparse matrix with possible span128 attempts the incompatible CPU0 queue once");
}
static void *replace_owner(void *arg) {
    cake_seat_update(0, 8, CAKE_SEAT_HOLD, 0); return NULL;
}
static void *release_owner(void *arg) {
    cake_seat_update(0, 7, CAKE_SEAT_RELEASE, *(u64 *)arg); return NULL;
}
static void seats(void) {
    reset();
    struct cake_groove gr = {.seat_cpu = 1, .seat_pid = 7};
    gr.seat_seq = cake_seat_update(0, 7, CAKE_SEAT_HOLD, 0);
    cake_seat_retire(&gr, 7, 2); /* A -> B, old owner disappears */
    assert(!gr.seat_cpu && !cake_seat_word && !cake.run[0].seat_pid);
    gr.seat_seq = cake_seat_update(1, 7, CAKE_SEAT_HOLD, 0); gr.seat_cpu = 2;
    cake_seat_update(1, 7, CAKE_SEAT_RUN, 0);
    assert(!cake_seat_word && cake.run[1].seat_pid == 7);
    cake_seat_retire(&gr, 7, 0); /* exit must clear even an unheld identity */
    assert(!cake.run[1].seat_pid && !gr.seat_cpu);
    cake_seat_update(0, 8, CAKE_SEAT_HOLD, 0); gr.seat_cpu = 1;
    cake_seat_retire(&gr, 7, 0);
    assert(cake.run[0].seat_pid == 8 && cake_seat_word == 1);
    fail_lookup = true; cake_seat_update(1, 7, CAKE_SEAT_HOLD, 0);
    assert(!cake.run[1].seat_pid && cake_seat_word == 1);
    fail_lookup = false;
    for (unsigned i = 0; i < 256; i++) {
        pthread_t a, b;
        u64 seq = cake_seat_update(0, 7, CAKE_SEAT_HOLD, 0);
        assert(!pthread_create(&a, NULL, replace_owner, NULL));
        assert(!pthread_create(&b, NULL, release_owner, &seq));
        assert(!pthread_join(a, NULL)); assert(!pthread_join(b, NULL));
        assert(cake.run[0].seat_pid == 8 && (cake_seat_word & 1));
    }
    puts("PASS: seat migration, exit after resume, replacement, missing storage/lock and concurrent owner retirement");
    for (u32 keep = 0; keep <= 2; keep++) {
        reset(); gr.seat_cpu = 1; gr.seat_pid = 7;
        gr.seat_seq = cake_seat_update(0, 7, CAKE_SEAT_HOLD, 0);
        /* Nonleader exec: exit, resume on the same CPU, or migrate. */
        cake_seat_retire(&gr, 8, keep);
        assert(!gr.seat_cpu && !cake.run[0].seat_pid && !cake_seat_word);
    }
    reset(); gr.seat_cpu = 1; gr.seat_pid = 7;
    gr.seat_seq = cake_seat_update(0, 7, CAKE_SEAT_HOLD, 0);
    cake_seat_retire(&gr, 7, 1);
    assert(gr.seat_cpu == 1 && cake.run[0].seat_pid == 7 && cake_seat_word == 1);
    cake_seat_update(0, 9, CAKE_SEAT_HOLD, 0);
    cake_seat_retire(&gr, 8, 1);
    assert(!gr.seat_cpu && cake.run[0].seat_pid == 9 && cake_seat_word == 1);
    reset(); gr.seat_cpu = 1; gr.seat_pid = 7;
    gr.seat_seq = cake_seat_update(0, 7, CAKE_SEAT_HOLD, 0);
    /* After exec releases PID7, a new task can reuse it before retirement. */
    u64 replacement = cake_seat_update(0, 7, CAKE_SEAT_HOLD, 0);
    assert(replacement != gr.seat_seq);
    cake_seat_retire(&gr, 8, 0);
    assert(!gr.seat_cpu && cake.run[0].seat_pid == 7 && cake_seat_word == 1);
    puts("PASS: PID exchange retires the acquisition while same-task resume, replacement owners and PID reuse keep their seats");
}
static void availability_and_rank(void) {
    reset(); assert(!cake_handoff_yields(0));
    current_task = &task;
    assert(!cake_handoff_yields(0)); /* existing vtime, but outside SCX */
    task.scx.flags = CAKE_TASK_QUEUED;
    assert(cake_handoff_yields(0));
    puts("PASS: absent/non-SCX occupant does not count as a proven handoff");
    reset(); cpu_sibling[0] = 4; cpu_sibling[4] = 0;
    assert(cake_taci(0, 0));
    assert(!(cake_idle_word() & 1));
    assert(!(cake_core_word() & 0x11));
    /* Empty dispatch: kernel repairs masks without a Cake idle callback. */
    kernel_idle |= 1; cake_core_free |= 0x11;
    assert((cake_idle_word() & 1) && (cake_core_word() & 0x11) == 0x11);
    reset(); cake_rank_tiers = 3; cpu_perf_known = 255;
    cpu_perf_tier[0] = 0x30; cpu_perf_tier[1] = 0x03; cpu_perf_tier[2] = 0xcc;
    for (u64 w = 1; w < 256; w++) {
        u64 expected = (w & 0x30) ? w & 0x30 : ((w & 3) ? w & 3 : w & 0xcc);
        assert(cake_rank_tier(w) == expected);
        u64 left = w;
        while (left) {
            s32 c = cake_pick_cold(left, 0, 0, 0);
            assert(left & (1ULL << c)); left &= ~(1ULL << c);
        }
    }
    assert(cake_rank_tier(0x101) == 0x101); /* unknown CPU never demoted */
    assert(cake_pick_cold(0x11, 1, 0, 0) == 0); /* whole core before rank */
    assert(cake_pick_cold(0x11, 0x11, 0x10, 0) == 0); /* seat before rank */
    assert(cake_claim_warm(&task, 2) == 2); /* warm before cold rank */
    puts("PASS: claim exclusion, SMT retirement, empty-dispatch recovery, 255 ranked affinity sets, full fallback and warm/seat/core precedence");
}
static void smt_expansion(void) {
    reset();
    for (u32 distance = 1; distance < 64; distance++) {
        u64 left = 0, right = 0;
        for (u32 cpu = 0; cpu < 64; cpu++) {
            if (cpu + distance < 64) {
                cpu_sibling[cpu] = (s32)(cpu + distance); left |= 1ULL << cpu;
            } else if (cpu >= distance) {
                cpu_sibling[cpu] = (s32)(cpu - distance); right |= 1ULL << cpu;
            } else cpu_sibling[cpu] = -1;
        }
        u64 word = 0;
        for (u32 sample = 0; sample < 256; sample++) {
            /* All basis vectors, their complements and deterministic words. */
            if (sample < 64) word = 1ULL << sample;
            else if (sample < 128) word = ~(1ULL << (sample - 64));
            else word = word * 6364136223846793005ULL + 1442695040888963407ULL;
            cake_smt_shift = 64;
            u64 expected = cake_smt_expand(word);
            cake_smt_shift = distance; cake_smt_left = left; cake_smt_right = right;
            assert(cake_smt_expand(word) == expected);
        }
    }
    cake_smt_shift = 0; cake_smt_left = cake_smt_right = 0;
    assert(cake_smt_expand(0) == 0 && cake_smt_expand(~0ULL) == ~0ULL);
    puts("PASS: folded SMT expansion equals the generic map for all 63 shifts, basis/complement/random masks and no-SMT identity");
}
static void home_core_claims(void) {
    reset(); cpu_sibling[0] = 4; cpu_sibling[4] = 0;
    assert(!cake_core_contended(0));
    /* The sibling is still physically idle, but another wake owns its claim. */
    assert(cake_taci(4, 0));
    assert(current_task == NULL && cake_core_contended(0));
    /* An empty dispatch repairs the kernel masks without update_idle. */
    kernel_idle |= 1ULL << 4; cake_core_free |= 0x11;
    assert(!cake_core_contended(0));
    /* A wider SMT group: a busy member beyond the one sibling Cake maps. */
    cpu_sibling[0] = 1; cake_core_free &= ~15ULL;
    assert(cake_core_contended(0));
    cpu_sibling[0] = -1;
    /* With no SMT the kernel supplies logical availability through the
     * same API, so a busy home must still fail the combined check. */
    assert(cake_core_contended(0));
    cake_core_free |= 1;
    assert(!cake_core_contended(0));
    assert(cake_core_contended(64));
    assert(cake_core_contended(-1));
    /* Preserve the existing wide-host path and its unknown-occupant result. */
    cake_one_word = false; cpu_sibling[65] = 66;
    assert(!cake_core_contended(65));
    current_task = &task;
    assert(cake_core_contended(65));
    assert(refs == 0);
    puts("PASS: one home snapshot rejects busy CPUs and pending sibling claims, accepts repaired masks, covers all SMT members and preserves the wide fallback");
}
static void core_irq_preferences(void) {
    reset();
    for (u32 c = 0; c < 8; c++) cpu_sibling[c] = c ^ 4;
    cake_smt_shift = 4; cake_smt_left = 15; cake_smt_right = 240;
    cpu_irq_hot_words[0] = 1ULL << 4;
    assert(cake_core_irq_bad(0) && cake_cpu_irq_bad(4) && !cake_cpu_irq_bad(0));
    assert(cake_claim_warm(&task, 0) == 1); /* dirty cached core loses to clean */
    cpu_irq_hot_words[0] = 0; cake_irq_live[4].depth = 1;
    assert(cake_core_irq_bad(0) && !cake_core_irq_bad(1));
    cake_irq_live[4].depth = 0;
    cpu_irq_hot_words[1] = 1;
    assert(cake_cpu_irq_bad(64) && !cake_cpu_irq_bad(0));
    unsigned cases = 0;
    for (u64 hot = 0; hot < 256; hot++) {
        cpu_irq_hot_words[0] = hot;
        u64 bad = hot | ((hot & 15) << 4) | ((hot & 240) >> 4);
        for (u64 allowed = 1; allowed < 256; allowed++) {
            u64 preferred = allowed & ~bad;
            u64 chosen = 1ULL << cake_pick_cold(allowed, allowed, 0, cake_smt_expand(hot));
            assert(chosen & allowed);
            assert(chosen & (preferred ? preferred : allowed));
            cases++;
        }
    }
    cpu_irq_hot_words[0] = 0x11;
    assert(cake_pick_cold(0x33, 0x11, 0, 0x11) == 0); /* whole core precedes IRQ */
    assert(cake_pick_cold(0x33, 0x33, 0x22, 0x11) == 0); /* seats precede IRQ */
    printf("PASS: %u IRQ/affinity combinations, noisy fallback, cached-core escape, live sibling IRQ, wide CPU words and unchanged core/seat priority\n", cases);
}
int main(void) {
    for (int i = 0; i < 64; i++) assert(!pthread_mutex_init(&locks[i].lock.mutex, NULL));
    placement(); pools(); frontier(); ring(); seats(); availability_and_rank(); smt_expansion(); home_core_claims(); core_irq_preferences(); forced_requeues(); pool_direct_claims(); slice_arithmetic();
    assert(refs == 0);
    puts("All policy assertions passed (offline only).");
}
