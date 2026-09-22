/* Offline helper model; functions.h is extracted from the current BPF source.
 * Consume enforces affinity and skips incompatible heads. Kick events are
 * serviced explicitly, including a concurrent head removal during consume. */
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "intf.h"
#include "stats.h"
#define __noinline
#define barrier_var(x) ((void)(x))
#define CAKE_KICK_IDLE 1
#define CAKE_WAKE_SYNC 1
#define CAKE_DSQ_LOCAL_ON (1ULL << 63)
#define CAKE_HINT_CONF_SHIFT 8
#define CAKE_HINT_CONF_MAX 3
#define CAKE_HINT_WOKE 1
#define CAKE_TASK_QUEUED 1
#define CAKE_ENQ_IMMED immed_flags
static u64 immed_flags = 1ULL << 33;

struct cpumask { u64 bits[1]; };
struct task_struct {
    struct cpumask *cpus_ptr;
    struct { u64 sum_exec_runtime; } se;
    struct { u64 dsq_vtime, flags; } scx;
    struct { s32 cpu; } thread_info;
    u64 nvcsw;
    int pid, nr_cpus_allowed;
};
struct cake_run_slot { u64 hint, woke, seat_pid, retake; };
struct cake_groove { u16 seat_cpu; s16 last_win; u32 seat_pid; u64 seat_seq; };
static struct { struct { u64 word; } wake_mark[MAX_LLCS];
    u64 qmask[QMASK_WORDS]; struct cake_run_slot run[MAX_CPUS]; } cake;
static u16 cpu_llc_domain[MAX_CPUS];
static u64 cake_idle_words[QMASK_WORDS], cake_seat_word, cpu_llc_word[MAX_CPUS];
static u8 cake_probe_pool_x[MAX_CPUS], cake_probe_busy_flag[MAX_CPUS];
static bool cake_one_word = true, cake_tog_g85 = true;
static bool cake_tog_probe;
static bool cake_tog_g89 = true;
static u32 nr_llcs = 1;
static struct cpumask masks[2];
static struct task_struct tasks[2];
static bool queued[2], remove_head, wall, starved, irq_bad, contended, claim;
static bool serial;
static int serving, events[512], tail, kicks, claims, storage_reads, inserted;
static int occupant_reads, preempts;
static u64 inserted_flags;
static struct task_struct *current_task;
static struct cake_groove groove;

static u32 cake_llc_of(s32 cpu) { return 0; }
static u64 cake_pool_dsq(u32 llc) { return LLC_WAKE_DSQ_BASE; }
static u32 cake_nrq(u64 dsq) { return dsq == LLC_WAKE_DSQ_BASE ? queued[0] + queued[1] : 0; }
static struct task_struct *cake_dsq_peek(u64 dsq) {
    if (dsq == LLC_WAKE_DSQ_BASE)
        for (int i = 0; i < 2; i++) if (queued[i]) return &tasks[i];
    return NULL;
}
static bool cake_move_to_local(u64 dsq) {
    if (remove_head) { queued[0] = false; remove_head = false; }
    if (dsq == LLC_WAKE_DSQ_BASE)
        for (int i = 0; i < 2; i++)
            if (queued[i] && ((masks[i].bits[0] >> serving) & 1)) {
                queued[i] = false;
                return true;
            }
    return false;
}
static void cake_kick(s32 cpu, u64 flags) {
    assert(cpu >= 0 && cpu < 4 && tail < 512);
    events[tail++] = cpu; kicks++;
}
static bool cake_ring_steal(u32 cpu) { return false; }
static bool cake_llc_pool_rescue(u32 llc) { return false; }
static bool cake_take_remote(u32 cpu) { return false; }
static bool cake_wake_starved(u32 llc) { return wall; }
static void cake_wake_idle_refresh(u32 llc, u32 cpu) {}
static void cake_wake_idle_stamp(u32 llc) {}
static void cake_wake_serve_stamp(u32 llc) {}
static void cake_wake_mark_set(u32 llc) { cake.wake_mark[llc].word = 1; }
static void cake_wake_mark_retire(u32 llc) {}
static void cake_qmark_publish(u32 cpu, bool nonempty) {}
static void cake_stat_inc(u32 stat) {}
static bool time_before(u64 a, u64 b) { return (s64)(a - b) < 0; }
static u64 cake_idle_word(void) { return cake_idle_words[0]; }
static u64 cake_core_word(void) { return cake_idle_word(); }
static u64 cake_smt_expand(u64 seats) { return seats; }
static u64 cpu_irq_hot_words[QMASK_WORDS];
static s32 cake_pick_cold(u64 w, u64 cores, u64 seats, u64 noisy) { return __builtin_ctzll(w); }
static struct cake_groove *cake_groove_of(struct task_struct *p) { storage_reads++; return &groove; }
static u32 bpf_get_smp_processor_id(void) { return 0; }
static bool cake_cpu_irq_bad(s32 cpu) { return irq_bad; }
static bool cake_core_irq_bad(s32 cpu) { return irq_bad; }
static bool bpf_cpumask_test_cpu(s32 cpu, const struct cpumask *mask) {
    return cpu >= 0 && cpu < 64 && ((mask->bits[0] >> cpu) & 1);
}
static bool cake_system_serial(void) { return serial; }
static bool cake_cpu_dsq_idle(u32 cpu) { return true; }
static u32 cake_local_nr(s32 cpu) { return 0; }
static bool cake_handoff_yields(s32 cpu) { return true; }
static void cake_direct_clamp(struct task_struct *p) {}
static void cake_dsq_insert(struct task_struct *p, u64 dsq, u64 slice, u64 flags) {
    inserted = (int)(dsq & ~CAKE_DSQ_LOCAL_ON);
    inserted_flags = flags;
}
static u64 cake_task_slice(struct task_struct *p) { return SLICE_NS; }
static void cake_probe_x(u32 site, s32 from, s32 to) {}
static struct task_struct *cake_cpu_curr(s32 cpu) { occupant_reads++; return current_task; }
static void cake_kick_preempt(s32 cpu) { preempts++; }
static bool cake_seat_blocks(s32 cpu, const struct task_struct *p, u32 site) {
    return cpu >= 0 && cpu < 64 && ((cake_seat_word >> cpu) & 1) &&
        cake.run[cpu].seat_pid != (u64)p->pid;
}
static bool cake_starved_turn(const struct task_struct *p) { return starved; }
static bool cake_core_contended(s32 cpu) {
    return contended || (cake_one_word &&
        (cpu < 0 || cpu >= 64 || !(cake_idle_words[0] & (1ULL << cpu))));
}
static bool cake_taci(s32 cpu, u32 site) { claims++; return claim; }
static s32 cake_claim_warm(struct task_struct *p, s32 gr) { return 3; }
#include "functions.h"

static void reset(void) {
    current_task = NULL; occupant_reads = preempts = 0;
    memset(&cake, 0, sizeof(cake)); memset(&groove, 0, sizeof(groove));
    memset(tasks, 0, sizeof(tasks));
    for (int i = 0; i < 2; i++) {
        tasks[i].cpus_ptr = &masks[i]; tasks[i].pid = i + 1;
    }
    for (int i = 0; i < MAX_CPUS; i++) cpu_llc_word[i] = 15;
    cake_idle_words[0] = 15; cake_seat_word = 0;
    queued[0] = queued[1] = remove_head = wall = starved = irq_bad = contended = false;
    serial = cake_tog_probe = false;
    claim = true; tail = kicks = claims = storage_reads = 0; inserted = -1;
    inserted_flags = 0;
}

static void dispatch_tests(void) {
    unsigned cases = 0;
    for (u64 seats = 1; seats < 15; seats++) {
        for (u64 aff = 1; aff < 16; aff++) {
            reset(); cake_seat_word = seats;
            masks[0].bits[0] = 15; masks[1].bits[0] = aff;
            queued[0] = queued[1] = true;
            for (int cpu = 0; cpu < 4; cpu++) events[tail++] = cpu;
            for (int i = 0; i < tail && (queued[0] || queued[1]); i++) {
                assert(tail < 512); serving = events[i];
                if (cake_dispatch_search(serving)) events[tail++] = serving;
            }
            assert(!queued[0] && !queued[1]); cases++;
        }
    }
    /* Old head allows CPU2. Another CPU consumes it during our failed move;
     * the new head allows CPU1 only. Forward must inspect the new head. */
    reset(); masks[0].bits[0] = 4; masks[1].bits[0] = 2;
    queued[0] = queued[1] = remove_head = true; serving = 0;
    assert(!cake_dispatch_search(0));
    assert(kicks == 1 && events[0] == 1);
    serving = 1; assert(cake_dispatch_search(1));
    /* No compatible idle CPU: don't send an unrelated CPU a kick. */
    reset(); masks[0].bits[0] = 2; queued[0] = true;
    cake_idle_words[0] = 13; serving = 0;
    assert(!cake_dispatch_search(0) && kicks == 0);
    reset(); masks[0].bits[0] = 15; queued[0] = wall = true;
    cake_seat_word = 1; serving = 0;
    assert(cake_dispatch_search(0) && kicks == 0);
    printf("dispatch: %u mixed-affinity seat cases plus head-race, busy-target, wall cases passed\n", cases);
}

static void select_tests(void) {
    for (unsigned supported = 0; supported < 2; supported++) {
    immed_flags = supported ? 1ULL << 33 : 0;
    for (unsigned bits = 0; bits < 512; bits++) {
        int result[2], attempts[2];
        for (int probe = 0; probe < 2; probe++) {
            reset(); cake_tog_probe = probe;
            bool stage = bits & 1, sync = bits & 2;
            starved = bits & 4; irq_bad = bits & 8; contended = bits & 16;
            claim = bits & 32; masks[0].bits[0] = (bits & 64) ? 15 : 13;
            cake_seat_word = (bits & 128) ? 2 : 0;
            tasks[0].se.sum_exec_runtime = stage ? SEAT_BURST_MIN_NS : 0;
            if (bits & 256) cake_idle_words[0] &= ~2ULL;
            result[probe] = cake_select_cpu(&tasks[0], 1, sync ? CAKE_WAKE_SYNC : 0);
            attempts[probe] = claims;
            assert(claims <= 1);
            assert(storage_reads == (result[probe] == 1 ? 0 : 1));
            bool ask = (!sync || stage) && !starved && !irq_bad &&
                (bits & 64) && !(bits & 128) && !(bits & 256);
            assert(result[probe] == ((ask && !contended && claim) ? 1 : 3));
            assert(inserted_flags == immed_flags);
        }
        assert(result[0] == result[1] && attempts[0] == attempts[1]);
    }
    reset(); serial = true; masks[0].bits[0] = 15;
    cake.run[0].hint = CAKE_HINT_CONF_MAX << CAKE_HINT_CONF_SHIFT;
    assert(cake_select_cpu(&tasks[0], 1, 0) == 0);
    assert(storage_reads == 0 && claims == 0);
    assert(inserted_flags == 0);
    }
    puts("select: 1024 feature/gate cases agree across probe settings; idle placements request immediate admission, serial queues intentionally");
}

static void retake_tests(void) {
    for (unsigned scenario = 0; scenario < 8; scenario++) {
        reset();
        struct task_struct *p = &tasks[0], *occupant = &tasks[1];
        p->se.sum_exec_runtime = SEAT_BURST_MIN_NS;
        p->scx.flags = occupant->scx.flags = CAKE_TASK_QUEUED;
        p->scx.dsq_vtime = occupant->scx.dsq_vtime = 1000;
        p->nr_cpus_allowed = occupant->nr_cpus_allowed = 4;
        masks[0].bits[0] = 15; cake_idle_words[0] = 13;
        cake.run[1].seat_pid = p->pid;
        current_task = occupant;
        switch (scenario) {
        case 1: occupant->scx.flags = 0; break; /* promoted to RT; old vtime remains */
        case 2: occupant->scx.dsq_vtime = 0; break;
        case 3: occupant->nr_cpus_allowed = 1; break;
        case 4: occupant->se.sum_exec_runtime = SEAT_BURST_MIN_NS; break;
        case 5: current_task = p; break;
        case 6: current_task = NULL; break;
        case 7: cake_seat_word = 2; break; /* nobody ran on the held seat */
        }
        s32 result = cake_select_cpu(p, 1, 0);
        bool allowed = scenario == 0;
        assert(result == (allowed ? 1 : 3));
        assert(preempts == allowed && cake.run[1].retake == allowed);
        assert(occupant_reads == (scenario == 7 ? 0 : 1));
        if (allowed) assert(inserted == 1 && storage_reads == 0 && inserted_flags == 0);
    }
    puts("retake: one occupant read; RT/unknown/pinned/stage/self/absent/held-seat cases preserve exclusion");
}

static void arithmetic_topology_tests(void) {
    reset();
    const u64 limit = ~0ULL / SEAT_BURST_MIN_NS;
    u64 ns[] = {0, 1, 2, 3000, limit - 1, limit, limit + 1, ~0ULL};
    for (unsigned i = 0; i < sizeof(ns) / sizeof(ns[0]); i++) {
        u64 n = ns[i] | 1, threshold = n * SEAT_BURST_MIN_NS;
        u64 runtimes[] = {0, ~0ULL, threshold - 1, threshold, threshold + 1};
        tasks[0].nvcsw = ns[i];
        for (unsigned j = 0; j < sizeof(runtimes) / sizeof(runtimes[0]); j++) {
            tasks[0].se.sum_exec_runtime = runtimes[j];
            assert(cake_stage(&tasks[0]) == (runtimes[j] / n >= SEAT_BURST_MIN_NS));
        }
    }
    for (int i = 0; i < MAX_CPUS; i++) cpu_llc_domain[i] = 0xffff;
    for (int i = 0; i < 128; i++) cpu_llc_domain[i] = (i % 64) / 4;
    for (int a = 0; a < 128; a++) for (int b = 0; b < 128; b++)
        assert(cake_cross_llc(a, b) == ((a % 64) / 4 != (b % 64) / 4));
    assert(!cake_cross_llc(-1, 0) && !cake_cross_llc(MAX_CPUS, 0));
    assert(!cake_cross_llc(0, 128) && !cake_cross_llc(128, 0));
    puts("stage: overflow boundaries exact; topology: all 16384 wide-host CPU pairs and unknown IDs passed");
}

int main(void) {
    arithmetic_topology_tests(); dispatch_tests(); select_tests(); retake_tests();
    return 0;
}
