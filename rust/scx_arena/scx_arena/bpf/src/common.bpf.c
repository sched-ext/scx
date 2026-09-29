/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2026 Meta Platforms, Inc. and affiliates.
 */
#include <scx/common.bpf.h>
#include <lib/sdt_task.h>

/*
 * Storage for the queue nodes declared by bpf_arena_spin_lock.h. Each program
 * linking the arena spinlock provides exactly one definition, so that the array
 * is emitted once rather than once per translation unit.
 */
struct arena_qnode __arena __hidden qnodes[_Q_MAX_CPUS][_Q_MAX_NODES];
