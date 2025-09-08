/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header defines the 32-bit dispatch queue (DSQ) ID encoding
 * scheme for scx_mitosis, using type fields to distinguish between
 * per-CPU and cell+L3 domain queues. It includes helper functions to
 * construct, validate, and parse these DSQ IDs for queue management.
 */
#pragma once

#include "intf.h"
#include "mitosis.bpf.h"

/*
 * ================================
 * BPF DSQ ID Layout (64 bits wide)
 * ================================
 *
 * Top-level format:
 *   [63] [62..0]
 *   [ B] [  ID ]
 *
 * If B == 1 it is a Built-in DSQ
 * -------------------------
 *   [63] [62] [61 .. 32]  [31..0]
 *   [ 1] [ L] [   R    ]  [  V  ]
 *
 *   - L (bit 62): LOCAL_ON flag
 *       If L == 1 -> V = CPU number
 *   - R (30 bits): reserved / unused
 *   - V (32 bits): value (e.g., CPU#)
 *
 * If B == 0 -> User-defined DSQ
 * -----------------------------
 * Only the low 32 bits are used.
 *
 *   [63     ..     32] [31..0]
 *   [  0s or unused  ] [ VAL ]
 *
 *   Mitosis uses VAL as follows:
 *
 *   [31..24] [23..0]
 *   [QTYPE ] [DATA ]
 *
 *   QTYPE encodes the queue type (exactly one bit set):
 *
 *     QTYPE = 0x1 -> Per-CPU Q
 *       [31 .. 24] [23 .. 16] [15    ..      0]
 *       [00000001] [00000000] [      CPU#     ]
 *       [Q-TYPE:1]
 *
 *     QTYPE = 0x2 -> Cell+L3 Q
 *       [31 .. 24] [23 .. 16] [15      ..    0]
 *       [00000010] [  CELL# ] [      L3ID     ]
 *       [Q-TYPE:2]
 *
 */

#define DSQ_ERROR 0xFFFFFFFF; /* Error value for DSQ functions */

/* DSQ type enumeration */
enum dsq_type {
	DSQ_UNKNOWN,
	DSQ_TYPE_CPU,
	DSQ_TYPE_CELL_L3,
};

/* DSQ ID structure using unions for type-safe access */
struct dsq_cpu {
	u32 cpu : 16;
	u32 unused : 8;
	u32 type : 8;
} __attribute__((packed));

struct dsq_cell_l3 {
	u32 l3 : 16;
	u32 cell : 8;
	u32 type : 8;
} __attribute__((packed));

union dsq_id {
	u32 raw;
	struct dsq_cpu cpu;
	struct dsq_cell_l3 cell_l3;
	struct {
		u32 data : 24;
		u32 type : 8;
	} common;
} __attribute__((packed));

/* Static assertions to ensure correct sizes */
/* Verify that all DSQ structures are exactly 32 bits */
_Static_assert(sizeof(struct dsq_cpu) == 4, "dsq_cpu must be 32 bits");
_Static_assert(sizeof(struct dsq_cell_l3) == 4, "dsq_cell_l3 must be 32 bits");
_Static_assert(sizeof(union dsq_id) == 4, "dsq_id union must be 32 bits");

/* Inline helper functions for DSQ ID manipulation */

// Is this a per CPU DSQ?
static inline bool is_cpu_dsq(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	return id.common.type == DSQ_TYPE_CPU;
}

// If this is a per cpu dsq, return the cpu
static inline u32 get_cpu_from_dsq(u32 dsq_id)
{
	union dsq_id id = { .raw = dsq_id };
	if (id.common.type != DSQ_TYPE_CPU)
		return DSQ_ERROR;
	return id.cpu.cpu;
}

/* Helper functions to construct DSQ IDs */
static inline u32 get_cpu_dsq_id(u32 cpu)
{
	if (cpu >= MAX_CPUS)
		return DSQ_ERROR;
	union dsq_id id = { .cpu = { .cpu = cpu, .unused = 0, .type = DSQ_TYPE_CPU } };
	return id.raw;
}

static inline u32 get_cell_l3_dsq_id(u32 cell, u32 l3)
{
	if (cell >= MAX_CELLS || l3 >= MAX_L3S)
		return DSQ_ERROR;
	union dsq_id id = { .cell_l3 = {.l3 = l3, .cell = cell, .type = DSQ_TYPE_CELL_L3 } };
	return id.raw;
}
