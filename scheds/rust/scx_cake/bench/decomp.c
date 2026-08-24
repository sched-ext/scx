/* decomp — split the sleeping-handoff cost into syscall / wakeup / switch.
 * DIAGNOSTIC ONLY. Interleaved rounds; report medians. */
#define _GNU_SOURCE
#include <errno.h>
#include <linux/futex.h>
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define N 200000

static inline uint64_t now_ns(void)
{ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts);
  return (uint64_t)ts.tv_sec*1000000000ull+ts.tv_nsec; }

static void pin(int c){cpu_set_t s;CPU_ZERO(&s);CPU_SET(c,&s);
  pthread_setaffinity_np(pthread_self(),sizeof s,&s);}

static _Atomic int fword;

/* 1. null syscall: getppid is not cached by glibc */
static double t_syscall(void)
{ uint64_t s=now_ns(); for(int i=0;i<N;i++) syscall(SYS_getppid);
  return (double)(now_ns()-s)/N; }

/* 2. FUTEX_WAKE with NO waiter: syscall + hash bucket lock, no wakeup */
static double t_futex_wake_empty(void)
{ uint64_t s=now_ns();
  for(int i=0;i<N;i++) syscall(SYS_futex,&fword,FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
  return (double)(now_ns()-s)/N; }

/* 3. sched_yield ping-pong, two threads pinned to ONE cpu:
 *    a full context switch with NO futex and NO wakeup path. */
static _Atomic uint64_t yturn; static int ycpu;
static void *yworker(void *a)
{ intptr_t me=(intptr_t)a; pin(ycpu);
  for(int i=0;i<N;i++){ while((atomic_load(&yturn)&1)!=(uint64_t)me) sched_yield();
    atomic_fetch_add(&yturn,1);} return NULL; }
static double t_ctxsw(void)
{ pthread_t t0,t1; ycpu=0; atomic_store(&yturn,0); uint64_t s=now_ns();
  pthread_create(&t0,NULL,yworker,(void*)0); pthread_create(&t1,NULL,yworker,(void*)1);
  pthread_join(t0,NULL); pthread_join(t1,NULL);
  return (double)(now_ns()-s)/(2.0*N); }

/* 4. full futex sleep/wake handoff round trip, unpinned */
static _Atomic int fq[2];
static void *fworker(void *a)
{ intptr_t me=(intptr_t)a;
  for(int i=0;i<N;i++){
    while(atomic_load(&fq[me])==0)
      syscall(SYS_futex,&fq[me],FUTEX_WAIT|FUTEX_PRIVATE_FLAG,0,NULL,NULL,0);
    atomic_store(&fq[me],0);
    atomic_store(&fq[1-me],1);
    syscall(SYS_futex,&fq[1-me],FUTEX_WAKE|FUTEX_PRIVATE_FLAG,1,NULL,NULL,0);
  } return NULL; }
static double t_futex_handoff(void)
{ pthread_t t0,t1; atomic_store(&fq[0],1); atomic_store(&fq[1],0);
  uint64_t s=now_ns();
  pthread_create(&t0,NULL,fworker,(void*)0); pthread_create(&t1,NULL,fworker,(void*)1);
  pthread_join(t0,NULL); pthread_join(t1,NULL);
  return (double)(now_ns()-s)/(2.0*N); }

static int cmp(const void*a,const void*b)
{ double x=*(const double*)a,y=*(const double*)b; return x<y?-1:x>y; }
static double med(double *v,int n){qsort(v,n,sizeof(double),cmp);return v[n/2];}

int main(void)
{
	enum{R=3};
	double a[R],b[R],c[R],d[R];
	for(int r=0;r<R;r++){            /* interleaved */
		a[r]=t_syscall(); b[r]=t_futex_wake_empty();
		c[r]=t_ctxsw();   d[r]=t_futex_handoff();
	}
	printf("null syscall (getppid)          %7.1f ns\n", med(a,R));
	printf("FUTEX_WAKE, no waiter           %7.1f ns\n", med(b,R));
	printf("ctx switch (yield, 1 cpu, 2 thr)%7.1f ns\n", med(c,R));
	printf("full futex sleep/wake handoff   %7.1f ns\n", med(d,R));
	return 0;
}
