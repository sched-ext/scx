---
title: LAVD simulator support
status: open
priority: 0
issue_type: epic
created_at: 2026-02-13T17:58:00.341650825+00:00
updated_at: 2026-02-13T17:58:00.341650825+00:00
---

# Description

Add scx_lavd scheduler support to scx_simulator. LAVD is ~7500 lines of BPF code across 11 files. Requires arena/SDT stubs, per-CPU map emulation, cpumask extensions, BPF timer API, tick support, and new ops callbacks.
