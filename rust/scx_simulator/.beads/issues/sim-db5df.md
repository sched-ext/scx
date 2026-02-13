---
title: LAVD wrapper.c + config.mk + Makefile integration
status: closed
priority: 0
issue_type: feature
created_at: 2026-02-13T18:13:24.003292326+00:00
updated_at: 2026-02-13T18:52:46.435585287+00:00
closed_at: 2026-02-13T18:52:46.435585187+00:00
---

# Description

Create schedulers/lavd/ with wrapper.c and config.mk. Handle all BPF/arena macro overrides. lavd_setup(nr_cpus) to init globals. Compile all 11 LAVD .bpf.c files. Guard div-by-zero.
