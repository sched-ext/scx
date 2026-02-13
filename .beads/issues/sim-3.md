---
title: BPF arena / SDT task allocator stubs
status: closed
priority: 0
issue_type: feature
depends_on:
  sim-1: parent-child
created_at: 2026-02-13T17:58:22.711679316+00:00
updated_at: 2026-02-13T17:59:37.191569091+00:00
closed_at: 2026-02-13T17:58:22.713476199+00:00
---

# Description

DONE. csrc/sim_sdt_stubs.c — hash table (2048 slots, open addressing) with scx_task_init, scx_task_alloc, scx_task_data, scx_task_free, scx_arena_subprog_init. Strong symbols override weak stubs in overrides.c. Compiled into both static lib (for unit tests) and each .so (for runtime). FFI declarations in ffi.rs. 3 unit tests in kfuncs.rs.
