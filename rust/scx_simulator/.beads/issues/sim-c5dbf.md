---
title: Bpftrace sched_class kprobes don't include PIDs, making per-task analysis difficult
status: open
priority: 2
issue_type: task
labels:
  - realism
created_at: 2026-02-13T21:26:58.753760749+00:00
updated_at: 2026-02-13T21:26:58.753760749+00:00
---

# Description

The trace_scx_ops.bt bpftrace script traces sched_class callbacks via kprobe, but these entry probes cannot dereference struct task_struct to extract PIDs (BPF complexity limits with many probes). PIDs only appear in kfunc fexit events (dsq_insert, task_cpu, etc.), which are a subset of all scheduling events. This makes it very difficult to reconstruct per-task scheduling lifecycles from the real trace. Possible fixes: (1) add tracepoint-based tracing for sched_switch/sched_wakeup alongside the kprobes, (2) use fewer probes to stay within complexity budget and add PID extraction to kretprobes, (3) correlate kfunc PIDs with surrounding sched_class events by timestamp proximity.
