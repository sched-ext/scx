---
title: Pass prev task to dispatch callback
status: closed
priority: 2
issue_type: bug
depends_on:
  sim-5a20c: related
created_at: 2026-02-13T13:04:36.633452243+00:00
updated_at: 2026-02-13T13:15:57.840914346+00:00
closed_at: 2026-02-13T13:15:57.840914306+00:00
---

# Description

The engine passes prev=NULL to cosmos_dispatch (engine.rs:576). The real kernel
passes the previously-running task (or NULL if CPU was idle). COSMOS uses prev
in dispatch for SMT contention re-slicing (line 997).

Fix:
- Track the previously-running task per CPU
- Pass it to dispatch as the second argument instead of null_mut()
- This enables the SMT contention re-slice path (once SMT is simulated)
