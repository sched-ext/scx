---
title: LAVD wrapper.c + config.mk + Makefile integration
status: open
priority: 0
issue_type: feature
depends_on:
  sim-1: parent-child
created_at: 2026-02-13T17:58:12.711162839+00:00
updated_at: 2026-02-13T17:59:37.189957907+00:00
---

# Description

Create schedulers/lavd/ directory with wrapper.c and config.mk. Handle BPF/arena macro overrides (__arena, __kptr, private(), __hidden, MEMBER_VPTR, WRITE_ONCE/READ_ONCE, UEI_DEFINE/UEI_RECORD, SEC(.maps), __arg_trusted, BPF_STRUCT_OPS_SLEEPABLE). Add lavd_setup(nr_cpus) to initialize globals (cpdom_ctxs, cpu_capacity, cpu_big, cpu_turbo, cpu_sibling, nr_llcs, nr_cpu_ids). Include path for scheds/rust/scx_lavd/src/bpf/. Guard against division-by-zero (BPF returns 0, native C crashes SIGFPE). Compile all 11 LAVD .bpf.c files.
