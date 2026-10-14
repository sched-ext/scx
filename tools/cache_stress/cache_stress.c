/*
 * cache_stress — multi-threaded shared-memory stress test for
 * verifying scx_lavd cache-aware scheduling.
 *
 * Each thread does random read-modify-write on a shared uint64_t array
 * sized to ~4 MB (typical LLC size).  Threads 0..(thr_per_group-1)
 * hammer the first half; threads thr_per_group..(nthreads-1) hammer
 * the second half, creating two working sets whose performance
 * benefits from staying on the same LLC domain.
 *
 * Output: per-thread ops/s and total ops/s, designed to be parsed by
 * run_test.sh.
 *
 * Build:  gcc -O2 -Wall -pthread -lm -o cache_stress cache_stress.c
 * Usage:  ./cache_stress [-t threads] [-d duration_sec] [-s size_mb]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sched.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>

#define DEFAULT_THREADS    8
#define DEFAULT_DURATION   30
#define DEFAULT_SIZE_MB    4

static volatile int  g_stop;
static uint64_t      g_size_mb    = DEFAULT_SIZE_MB;
static int           g_nthreads   = DEFAULT_THREADS;

static uint64_t     *g_shared;
static uint64_t      g_nelems;

struct thread_arg {
    int       tid;
    int       group;
    uint64_t  ops;
};

static inline uint64_t xorshift64(uint64_t *state)
{
    uint64_t x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    return x;
}

static void *worker(void *arg_)
{
    struct thread_arg *a = arg_;
    uint64_t state = (uint64_t)(a->tid + 1) * 0x9e3779b97f4a7c15ULL;
    uint64_t half = g_nelems / 2;
    uint64_t base = (a->group == 0) ? 0 : half;
    uint64_t range = half;
    uint64_t ops = 0;

    while (!__atomic_load_n(&g_stop, __ATOMIC_ACQUIRE)) {
        uint64_t idx = base + (xorshift64(&state) % range);
        __atomic_fetch_add(&g_shared[idx], 1, __ATOMIC_RELAXED);
        ops++;
    }

    a->ops = ops;
    return NULL;
}

static double ts_diff_sec(struct timespec *a, struct timespec *b)
{
    return (b->tv_sec - a->tv_sec) + (b->tv_nsec - a->tv_nsec) * 1e-9;
}

static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [-t threads] [-d duration_sec] [-s size_mb]\n"
        "  -t  number of threads (default %d)\n"
        "  -d  run duration in seconds (default %d)\n"
        "  -s  shared array size in MiB (default %d)\n",
        prog, DEFAULT_THREADS, DEFAULT_DURATION, DEFAULT_SIZE_MB);
}

int main(int argc, char **argv)
{
    int duration = DEFAULT_DURATION;
    int opt;

    while ((opt = getopt(argc, argv, "t:d:s:h")) != -1) {
        switch (opt) {
        case 't': g_nthreads = atoi(optarg); break;
        case 'd': duration = atoi(optarg); break;
        case 's': g_size_mb = strtoul(optarg, NULL, 0); break;
        case 'h': default: usage(argv[0]); return (opt == 'h') ? 0 : 1;
        }
    }

    g_size_mb  = g_size_mb  ? g_size_mb  : DEFAULT_SIZE_MB;
    g_nthreads = g_nthreads  ? g_nthreads : DEFAULT_THREADS;
    duration   = duration    ? duration   : DEFAULT_DURATION;

    g_nelems = (g_size_mb * 1024 * 1024) / sizeof(uint64_t);
    if (g_nelems < 256) {
        fprintf(stderr, "array too small (min 2 KiB)\n");
        return 1;
    }

    g_shared = mmap(NULL, g_nelems * sizeof(uint64_t),
                    PROT_READ | PROT_WRITE,
                    MAP_SHARED | MAP_ANONYMOUS, -1, 0);
    if (g_shared == MAP_FAILED) {
        perror("mmap");
        return 1;
    }
    memset(g_shared, 0, g_nelems * sizeof(uint64_t));

    int thr_per_group = g_nthreads / 2;
    if (thr_per_group < 1)
        thr_per_group = 1;

    printf("cache_stress: %d threads, %lu MiB shared array, %d s\n",
           g_nthreads, g_size_mb, duration);
    printf("  group-0: threads 0..%d (first half)\n", thr_per_group - 1);
    printf("  group-1: threads %d..%d (second half)\n",
           thr_per_group, g_nthreads - 1);

    struct thread_arg args[g_nthreads];
    pthread_t        tids[g_nthreads];

    for (int i = 0; i < g_nthreads; i++) {
        args[i].tid   = i;
        args[i].group = (i < thr_per_group) ? 0 : 1;
        args[i].ops   = 0;
    }

    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (int i = 0; i < g_nthreads; i++)
        pthread_create(&tids[i], NULL, worker, &args[i]);

    sleep(duration);
    __atomic_store_n(&g_stop, 1, __ATOMIC_RELEASE);

    for (int i = 0; i < g_nthreads; i++)
        pthread_join(tids[i], NULL);

    clock_gettime(CLOCK_MONOTONIC, &t1);
    double elapsed = ts_diff_sec(&t0, &t1);

    uint64_t total_ops = 0;
    printf("\n--- results ---\n");
    printf("thread_id  group       ops      ops/s\n");
    for (int i = 0; i < g_nthreads; i++) {
        double ops_s = args[i].ops / elapsed;
        printf("    %2d       %d    %10lu  %10.0f\n",
               args[i].tid, args[i].group, args[i].ops, ops_s);
        total_ops += args[i].ops;
    }

    printf("----------------------------------------\n");
    printf("total: %lu ops in %.3f s => %.0f ops/s\n",
           total_ops, elapsed, total_ops / elapsed);

    munmap(g_shared, g_nelems * sizeof(uint64_t));
    return 0;
}