// Integration example for sched-ext/scx schedulers (Layer 3).
// Add to scx_bpfland.bpf.c or scx_qmap.bpf.c after #include <scx/common.bpf.h>:
//
//   #include <scx/scx_rt_guard.bpf.h>
//   SCX_RT_GUARD_SCHED_SWITCH_PROG(bpfland_rt_guard_switch)
//
// Requires kernel >= 6.19 (scx_bpf_reenqueue_local from any context).
// Complements ext_server (Layer 1) — mandatory for per-CPU kthread progress.

#include <scx/common.bpf.h>
#include <scx/compat.bpf.h>
#include <scx/scx_rt_guard.bpf.h>

char _license[] SEC("license") = "GPL";

SCX_RT_GUARD_SCHED_SWITCH_PROG(bpfland_rt_guard_switch)
