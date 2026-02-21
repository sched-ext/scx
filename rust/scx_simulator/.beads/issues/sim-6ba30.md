---
title: LAVD simulator support
status: open
priority: 0
issue_type: epic
depends_on:
  sim-d9988: related
created_at: 2026-02-13T17:58:00.341650825+00:00
updated_at: 2026-02-19T15:30:00.000000000+00:00
---

> **CLOSURE POLICY:** This issue tracks LAVD scheduler coverage and may only
> be closed when **100% line coverage** is achieved. Until then, update this
> issue with current coverage metrics and remaining blockers after each
> significant change.

# Description

Add scx_lavd scheduler support to scx_simulator. LAVD is ~7500 lines of BPF code across 11 files. Requires arena/SDT stubs, per-CPU map emulation, cpumask extensions, BPF timer API, tick support, and new ops callbacks.

## Current State (2026-02-19)

**151 integration tests** in `tests/lavd.rs`.

### Completed Infrastructure

- ✅ sim-64652: ops.dequeue callback
- ✅ sim-b89a6: ops.update_idle callback
- ✅ sim-2db12: ops.exit_task callback
- ✅ sim-fa170: __COMPAT_scx_bpf_dsq_peek kfunc

### Remaining Gaps

- sim-d9988: Full BPF arena support (current stubs sufficient for basic LAVD)

### Coverage Metrics

TODO: Run coverage report and update with line/branch/function coverage.

### Next Steps

1. Run coverage report on LAVD BPF files
2. Identify uncovered code paths
3. Add tests or infrastructure to improve coverage
