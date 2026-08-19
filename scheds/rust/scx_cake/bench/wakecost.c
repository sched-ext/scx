/* wakecost — the SENDER-SIDE wakeup path, measured directly.
 *
 * Thread A times the FUTEX_WAKE syscall itself while B is genuinely parked.
 * That interval is: syscall + futex hash/dequeue + try_to_wake_up +
 * select_task_rq (ops.select_cpu) + enqueue (ops.enqueue) + resched/IPI-send.
 * It does NOT include the IPI receive, B's context switch, or B's syscall
 * return -- so it is the wakeup path alone, not a handoff.
 *
 * Only samples where FUTEX_WAKE returned 1 are counted, so every recorded
 * sample really did wake a parked task. A no-waiter baseline is measured in
 * the same run for subtraction. A and B are on different CPUs so A is never
 * preempted mid-measurement.  DIAGNOSTIC ONLY.
 */
#define _GNU_SOURCE
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>
#include <x86intrin.h>

#define N 60000
static double tsc_hz;
static inline uint64_t rd(void){unsigned a;return __rdtscp(&a);}
static void pin(int c){cpu_set_t s;CPU_ZERO(&s);CPU_SET(c,&s);
  pthread_setaffinity_np(pthread_self(),sizeof s,&s);}
static uint64_t now_ns(void){struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);
  return (uint64_t)t.tv_sec*1000000000ull+t.tv_nsec;}

static _Atomic int slot;       /* futex word B parks on */
static _Atomic int b_parking;  /* B announces it is about to park */
static _Atomic int done;
static int bcpu;

static void *bthread(void *a)
{
	(void)a; pin(bcpu);
	while (!atomic_load(&done)) {
		atomic_store(&slot, 0);
		atomic_store(&b_parking, 1);
		while (atomic_load(&slot) == 0 && !atomic_load(&done))
			syscall(SYS_futex, &slot, FUTEX_WAIT|FUTEX_PRIVATE_FLAG, 0, NULL, NULL, 0);
	}
	return NULL;
}

static int cmpu(const void*x,const void*y)
{uint64_t a=*(const uint64_t*)x,b=*(const uint64_t*)y;return a<b?-1:a>b;}

int main(int argc, char **argv)
{
	bcpu = argc > 1 ? atoi(argv[1]) : 2;
	pin(0);
	uint64_t n0=now_ns(),c0=rd();
	struct timespec sl={0,150000000}; nanosleep(&sl,NULL);
	tsc_hz=(double)(rd()-c0)*1e9/(double)(now_ns()-n0);

	uint64_t t=rd(); for(int i=0;i<200000;i++){uint64_t v=rd();(void)v;}
	double rdov=(rd()-t)*1e9/tsc_hz/200000.0;

	/* no-waiter baseline */
	static uint64_t base[N];
	for (int i=0;i<N;i++){ uint64_t s=rd();
		syscall(SYS_futex,&slot,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
		base[i]=rd()-s; }

	pthread_t b; pthread_create(&b,NULL,bthread,NULL);

	static uint64_t d[N]; int n=0;
	for (int i=0;i<N;i++){
		while(!atomic_load(&b_parking)) __builtin_ia32_pause();
		for(int k=0;k<3000;k++) __builtin_ia32_pause();  /* let B truly park */
		atomic_store(&b_parking,0);
		atomic_store(&slot,1);
		uint64_t s=rd();
		long r=syscall(SYS_futex,&slot,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
		uint64_t e=rd();
		if (r==1) d[n++]=e-s;          /* only real wakeups count */
	}
	atomic_store(&done,1); atomic_store(&slot,1);
	syscall(SYS_futex,&slot,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
	pthread_join(b,NULL);

	qsort(base,N,8,cmpu); qsort(d,n,8,cmpu);
	double k=1e9/tsc_hz;
	printf("rdtscp overhead                 %6.1f ns (subtracted below)\n", rdov);
	printf("FUTEX_WAKE, no waiter           %6.1f ns  (p50)\n", base[N/2]*k-rdov);
	printf("FUTEX_WAKE, REAL wakeup cpu%-2d    %6.1f ns  (p50)   n=%d/%d\n",
	       bcpu, d[n/2]*k-rdov, n, N);
	printf("   p10 %6.1f   p90 %6.1f   p99 %6.1f ns\n",
	       d[n/10]*k-rdov, d[(int)(n*0.9)]*k-rdov, d[(int)(n*0.99)]*k-rdov);
	printf("   => wakeup path alone (minus syscall+futex): %6.1f ns\n",
	       (d[n/2]-base[N/2])*k);
	return 0;
}
