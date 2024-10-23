/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Rorke: A special purpose scheduler for hypervisors
 * TODO: Add a proper description
 *
 * Copyright(C) 2024 Vahab Jabrayilov<vjabrayilov@cs.columbia.edu>
 * Influenced by the scx_central & scx_bpfland schedulers
 */

#include <scx/common.bpf.h>
#include <scx/ravg_impl.bpf.h>
#include "intf.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>
#include <stdbool.h>

#include "intf.h"

char _license[] SEC("license") = "GPL";

UEI_DEFINE(uei);

/*
 * const volatiles are set again during initialization
 * here we assign values just to pass the verifier
 */
const volatile u32 central_cpu = 0;
const volatile u32 nr_cpus = 1;
const volatile u32 nr_vms = 1;
const volatile u64 timer_interval_ns = 100000;

const volatile u64 vms[MAX_VMS];
const volatile u64 cpu_to_vm[MAX_CPUS];

const volatile u32 debug = 0;

bool timer_pinned = true;
u64 nr_total, nr_locals, nr_queued, nr_lost_pids;
u64 nr_timers, nr_dispatches, nr_mismatches, nr_retries;
u64 nr_overflows;

/* Scheduling statistics */
volatile u64 nr_direct_to_idle_dispatches, nr_kthread_dispatches,
    nr_vm_dispatches, nr_running;

struct global_timer {
  struct bpf_timer timer;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, u32);
  __type(value, struct global_timer);
} global_timer SEC(".maps");

/*
 * Per-CPU context.
 */
struct cpu_ctx {
  u64 last_running;
  u64 kicked;
  u32 vm_id;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct cpu_ctx);
  __uint(max_entries, 1);
} cpu_ctx_stor SEC(".maps");

/*
 * Return a CPU context.
 */
struct cpu_ctx* try_lookup_cpu_ctx(s32 cpu) {
  const u32 idx = 0;
  return bpf_map_lookup_percpu_elem(&cpu_ctx_stor, &idx, cpu);
}

/*
 * Per-task local storage.
 */
struct task_ctx {};

/* Map that contains task-local storage. */
struct {
  __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
  __uint(map_flags, BPF_F_NO_PREALLOC);
  __type(key, int);
  __type(value, struct task_ctx);
} task_ctx_stor SEC(".maps");

/*
 * Return a local task context from a generic task.
 */
struct task_ctx* try_lookup_task_ctx(const struct task_struct* p) {
  return bpf_task_storage_get(&task_ctx_stor, (struct task_struct*)p, 0, 0);
}

/*
 * Return true if the target task @p is a kernel thread.
 */
static inline bool is_kthread(const struct task_struct* p) {
  return p->flags & PF_KTHREAD;
}

/*
 * Allocate/re-allocate a new cpumask.
 */
static int calloc_cpumask(struct bpf_cpumask** p_cpumask) {
  struct bpf_cpumask* cpumask;

  cpumask = bpf_cpumask_create();
  if (!cpumask)
    return -ENOMEM;

  cpumask = bpf_kptr_xchg(p_cpumask, cpumask);
  if (cpumask)
    bpf_cpumask_release(cpumask);

  return 0;
}

static s32 pick_idle_cpu(struct task_struct* p, s32 prev_cpu, u64 wake_flags) {
  if (scx_bpf_test_and_clear_cpu_idle(prev_cpu))
    return prev_cpu;

  if (p->nr_cpus_allowed == 1 || p->migration_disabled)
    return -EBUSY;

  return scx_bpf_pick_idle_cpu(p->cpus_ptr, 0);
}

s32 BPF_STRUCT_OPS(rorke_select_cpu,
                   struct task_struct* p,
                   s32 prev_cpu,
                   u64 wake_flags) {
  s32 cpu;

  cpu = pick_idle_cpu(p, prev_cpu, wake_flags);
  if (cpu >= 0) {
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF, 0);
    __sync_fetch_and_add(&nr_direct_to_idle_dispatches, 1);
    dbg("rorke_select_cpu: VM: %d, vCPU: %d, prev_cpu: %d direct dispatch to "
        "idle cpu: %d",
        p->tgid, p->pid, prev_cpu, cpu);

    return cpu;
  }

  return prev_cpu;
}

/*
 * Wake up an idle CPU for task @p.
 */
static void kick_task_cpu(struct task_struct* p) {
  s32 cpu = scx_bpf_task_cpu(p);

  cpu = pick_idle_cpu(p, cpu, 0);
  if (cpu >= 0)
    scx_bpf_kick_cpu(cpu, 0);
}

/*
 * Dispatch all the other tasks that were not dispatched directly in
 * select_cpu().
 */
void BPF_STRUCT_OPS(rorke_enqueue, struct task_struct* p, u64 enq_flags) {
  s32 pid = p->pid;
  s32 tgid = p->tgid;

  /*
   * Push per-cpu kthreads at the head of local dsq's and preempt the
   * corresponding CPU. This ensures that e.g. ksoftirqd isn't blocked
   * behind other threads which is necessary for forward progress
   * guarantee as we depend on the BPF timer which may run from ksoftirqd.
   */
  if (is_kthread(p) && p->nr_cpus_allowed == 1) {
    trace("rorke_enqueue: enqueued local kthread %d", pid);
    scx_bpf_dispatch(p, SCX_DSQ_LOCAL, SCX_SLICE_INF,
                     enq_flags | SCX_ENQ_PREEMPT);
    __sync_fetch_and_add(&nr_kthread_dispatches, 1);
    return;
  }

  trace("rorke_enqueue: enqueued VM: %d vCPU: %d", tgid, pid);
  scx_bpf_dispatch(p, tgid, SCX_SLICE_INF, enq_flags);
  __sync_fetch_and_add(&nr_vm_dispatches, 1);

  /*
   * If there is an idle cpu available for the task, wake it up.
   */
  kick_task_cpu(p);
}

void BPF_STRUCT_OPS(rorke_dispatch, s32 cpu, struct task_struct* prev) {
  /* TODO: replace following with per-cpu context */
  s32 vm_id = cpu < nr_cpus ? cpu_to_vm[cpu] : 0;
  if (vm_id == 0) {
    return;
  }

  if (scx_bpf_consume(vm_id)) {
    trace("rorke_dispatch: consumed from VM - %d", vm_id);
    return;
  }

  dbg("rorke_dispatch: empty... didn't consumed from VM - %d", vm_id);
}

void BPF_STRUCT_OPS(rorke_running, struct task_struct* p) {
  trace("rorke_running: VM: %d, vCPU: %d", p->tgid, p->pid);
  u64 now = bpf_ktime_get_ns();
  s32 cpu = scx_bpf_task_cpu(p);
  struct cpu_ctx* cctx = try_lookup_cpu_ctx(cpu);

  if (!cctx)
    return;

  cctx->last_running = now;
  __sync_fetch_and_add(&nr_running, 1);
}

void BPF_STRUCT_OPS(rorke_stopping, struct task_struct* p, bool runnable) {
  trace("rorke_stopping: VM: %d, vCPU: %d, runnable: %d", p->tgid, p->pid,
        runnable);
  __sync_fetch_and_sub(&nr_running, 1);
}

s32 BPF_STRUCT_OPS(rorke_init_task,
                   struct task_struct* p,
                   struct scx_init_task_args* args) {
  return 0;
}

void BPF_STRUCT_OPS(rorke_exit_task,
                    struct task_struct* p,
                    struct scx_exit_task_args* args) {}

/*
 * TODO: Add description for timer functionality
 */
static int global_timer_fn(void* map, int* key, struct bpf_timer* timer) {
  trace("global_timer_fn: timer fired");

  u64 now = bpf_ktime_get_ns();
  s32 current_cpu = bpf_get_smp_processor_id();
  struct cpu_ctx* cctx;
  u64 delta;

  if (timer_pinned && (current_cpu != central_cpu)) {
    scx_bpf_error("Central Timer ran on CPU %d, not central CPU %d\n",
                  current_cpu, central_cpu);
    return 0;
  }

  bpf_for(current_cpu, 0, nr_cpus) {
    if (current_cpu == central_cpu)
      continue;

    cctx = try_lookup_cpu_ctx(current_cpu);
    if (!cctx)
      continue;

    delta = now - cctx->last_running;
    if (delta < timer_interval_ns)
      continue;

    if (scx_bpf_dsq_nr_queued(SCX_DSQ_LOCAL_ON | current_cpu))
      trace("global_timer_fn: local non-empty, will kick CPU %d", current_cpu);
    else if (scx_bpf_dsq_nr_queued(cctx->vm_id))
      trace("global_timer_fn: VM %d queue non-empty, will kick CPU %d",
            cctx->vm_id, current_cpu);
    else {
      trace("global_timer_fn: nothing to do... skipping CPU %d", current_cpu);
      continue;
    }

    scx_bpf_kick_cpu(current_cpu, SCX_KICK_PREEMPT);
    cctx->kicked++;
    trace("global_timer_fn: kicked CPU %d", current_cpu);
  }

  bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
  return 0;
}

s32 BPF_STRUCT_OPS_SLEEPABLE(rorke_init) {
  int ret;

  /* Create DSQ per VM */
  u32 i;
  bpf_for(i, 0, nr_vms) {
    ret = scx_bpf_create_dsq(vms[i], -1);
    if (ret) {
      scx_bpf_error("Failed to create DSQ for VM %lld", vms[i]);
      return ret;
    }
    info("Created DSQ for VM %d", vms[i]);
  }

  /* Setup timer */
  struct bpf_timer* timer;
  u32 key = 0;
  timer = bpf_map_lookup_elem(&global_timer, &key);
  if (!timer) {
    info("Failed to lookup timer");
    return -ESRCH;
  }

  if (bpf_get_smp_processor_id() != central_cpu) {
    scx_bpf_error("Fatal: init on non-central CPU");
    return EINVAL;
  }

  bpf_timer_init(timer, &global_timer, CLOCK_MONOTONIC);
  bpf_timer_set_callback(timer, global_timer_fn);
  info("Initialized timer\n");

  ret = bpf_timer_start(timer, timer_interval_ns, BPF_F_TIMER_CPU_PIN);
  /*
   * BPF_F_TIMER_CPU_PIN is not supported in all kernels (>= 6.7). If we're
   * running on an older kernel, it'll return -EINVAL
   * Retry w/o BPF_F_TIMER_CPU_PIN
   */
  if (ret == -EINVAL) {
    timer_pinned = false;
    ret = bpf_timer_start(timer, timer_interval_ns, 0);
  }
  if (ret)
    scx_bpf_error("bpf_timer_start failed (%d)", ret);
  info("Started timer -- rorke_init successfully finished");

  return ret;
}

void BPF_STRUCT_OPS(rorke_exit, struct scx_exit_info* ei) {
  info("Exiting rorke");
  UEI_RECORD(uei, ei);
}

SCX_OPS_DEFINE(rorke,
               /*
                * We are offloading all scheduling decisions to the central CPU
                * and thus being the last task on a given CPU doesn't mean
                * anything special. Enqueue the last tasks like any other tasks.
                */

               .flags = SCX_OPS_ENQ_LAST,
               .select_cpu = (void*)rorke_select_cpu,
               .enqueue = (void*)rorke_enqueue,
               .dispatch = (void*)rorke_dispatch,
               .running = (void*)rorke_running,
               .stopping = (void*)rorke_stopping,
               .init_task = (void*)rorke_init_task,
               .exit_task = (void*)rorke_exit_task,
               .init = (void*)rorke_init,
               .exit = (void*)rorke_exit,
               .name = "rorke");
