/* floor_ladder — the handoff cost ladder, hardware floor to scheduler path.
 * DIAGNOSTIC ONLY. Interleaved rounds so shared host noise hits every rung. */
#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <x86intrin.h>

#define ITERS 100000
#define WARMUP 2000
#define ROUNDS 3

static double tsc_hz;

static inline uint64_t rdtsc_s(void) { unsigned a; return __rdtscp(&a); }

static inline uint64_t now_ns(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void pin(int cpu)
{
	cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s);
	pthread_setaffinity_np(pthread_self(), sizeof(s), &s);
}

static int cmp_u64(const void *a, const void *b)
{ uint64_t x=*(const uint64_t*)a,y=*(const uint64_t*)b; return x<y?-1:x>y; }

/* ---------------- SPIN handoff: no kernel, rdtscp-stamped ---------------- */
struct spinctx { _Atomic uint64_t turn; _Atomic uint64_t stamp; int cpu[2];
		 uint64_t *d[2]; };
static void *spin_worker(void *arg)
{
	struct spinctx *x = arg;
	static _Atomic int seq;
	int me = atomic_fetch_add(&seq, 1) & 1;
	pin(x->cpu[me]);
	uint64_t *out = x->d[me];
	for (int i = 0; i < ITERS + WARMUP; i++) {
		while ((atomic_load_explicit(&x->turn, memory_order_acquire) & 1) != (uint64_t)me)
			__builtin_ia32_pause();
		uint64_t woke = rdtsc_s();
		if (i >= WARMUP) out[i - WARMUP] = woke - atomic_load_explicit(&x->stamp, memory_order_relaxed);
		atomic_store_explicit(&x->stamp, rdtsc_s(), memory_order_relaxed);
		atomic_fetch_add_explicit(&x->turn, 1, memory_order_release);
	}
	return NULL;
}

/* --------------- FUTEX/condvar handoff: the real shape ------------------ */
struct fctx { pthread_mutex_t m; pthread_cond_t c; int turn; uint64_t sig;
	      int cpu[2]; uint64_t *d[2]; _Atomic int seq; };
static void *futex_worker(void *arg)
{
	struct fctx *x = arg;
	int me = atomic_fetch_add(&x->seq, 1) & 1;
	if (x->cpu[me] >= 0) pin(x->cpu[me]);
	uint64_t *out = x->d[me];
	pthread_mutex_lock(&x->m);
	for (int i = 0; i < ITERS + WARMUP; i++) {
		while (x->turn != me) pthread_cond_wait(&x->c, &x->m);
		uint64_t woke = now_ns();
		if (i >= WARMUP) out[i - WARMUP] = woke - x->sig;
		x->sig = now_ns();
		x->turn = 1 - me;
		pthread_cond_signal(&x->c);
	}
	pthread_mutex_unlock(&x->m);
	return NULL;
}

static uint64_t *bufA, *bufB, *all;

static void report(const char *name, int is_tsc, uint64_t *acc, size_t n)
{
	qsort(acc, n, sizeof(uint64_t), cmp_u64);
	double k = is_tsc ? 1e9 / tsc_hz : 1.0;
	printf("%-34s p50 %7.1f  p90 %7.1f  p99 %7.1f  p999 %8.1f  ns\n",
	       name, acc[n/2]*k, acc[(size_t)(n*.90)]*k, acc[(size_t)(n*.99)]*k,
	       acc[(size_t)(n*.999)]*k);
}

static void run_spin(int c0, int c1, uint64_t *acc, size_t *off)
{
	struct spinctx x = {0}; x.cpu[0]=c0; x.cpu[1]=c1; x.d[0]=bufA; x.d[1]=bufB;
	atomic_store(&x.stamp, rdtsc_s());
	pthread_t t0,t1;
	pthread_create(&t0,NULL,spin_worker,&x); pthread_create(&t1,NULL,spin_worker,&x);
	pthread_join(t0,NULL); pthread_join(t1,NULL);
	memcpy(acc+*off, bufA, ITERS*8); *off+=ITERS;
	memcpy(acc+*off, bufB, ITERS*8); *off+=ITERS;
}
static void run_futex(int c0, int c1, uint64_t *acc, size_t *off)
{
	struct fctx x; memset(&x,0,sizeof x);
	pthread_mutex_init(&x.m,NULL); pthread_cond_init(&x.c,NULL);
	x.cpu[0]=c0; x.cpu[1]=c1; x.d[0]=bufA; x.d[1]=bufB; x.sig=now_ns();
	pthread_t t0,t1;
	pthread_create(&t0,NULL,futex_worker,&x); pthread_create(&t1,NULL,futex_worker,&x);
	pthread_join(t0,NULL); pthread_join(t1,NULL);
	memcpy(acc+*off, bufA, ITERS*8); *off+=ITERS;
	memcpy(acc+*off, bufB, ITERS*8); *off+=ITERS;
}

int main(void)
{
	bufA=malloc(ITERS*8); bufB=malloc(ITERS*8);
	/* calibrate TSC */
	uint64_t n0=now_ns(), c0=rdtsc_s();
	struct timespec sl={0,200000000}; nanosleep(&sl,NULL);
	uint64_t n1=now_ns(), c1=rdtsc_s();
	tsc_hz = (double)(c1-c0)*1e9/(double)(n1-n0);
	printf("TSC %.3f GHz\n", tsc_hz/1e9);

	uint64_t t=rdtsc_s(); for(int i=0;i<1000000;i++){uint64_t v=rdtsc_s();(void)v;}
	printf("rdtscp            : %5.1f ns/call\n",(rdtsc_s()-t)*1e9/tsc_hz/1e6);
	uint64_t s=now_ns(); for(int i=0;i<1000000;i++){uint64_t v=now_ns();(void)v;}
	printf("clock_gettime vDSO: %5.1f ns/call\n\n",(double)(now_ns()-s)/1e6);

	enum { NCFG = 6 };
	struct { const char *name; int spin, a, b; } cfg[NCFG] = {
		{"SPIN   SMT siblings (0,8)",       1, 0, 8},
		{"SPIN   same-CCX cores (0,1)",     1, 0, 1},
		{"FUTEX  same CPU (0,0)",           0, 0, 0},
		{"FUTEX  SMT siblings (0,8)",       0, 0, 8},
		{"FUTEX  same-CCX cores (0,1)",     0, 0, 1},
		{"FUTEX  unpinned (as scored)",     0,-1,-1},
	};
	static uint64_t acc[NCFG][2*ITERS*ROUNDS];
	size_t off[NCFG] = {0};
	for (int r = 0; r < ROUNDS; r++)          /* interleaved */
		for (int i = 0; i < NCFG; i++)
			cfg[i].spin ? run_spin(cfg[i].a,cfg[i].b,acc[i],&off[i])
				    : run_futex(cfg[i].a,cfg[i].b,acc[i],&off[i]);
	for (int i = 0; i < NCFG; i++)
		report(cfg[i].name, cfg[i].spin, acc[i], off[i]);
	return 0;
}
