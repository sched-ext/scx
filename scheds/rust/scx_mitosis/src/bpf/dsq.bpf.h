/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * This software may be used and distributed according to the terms of the
 * GNU General Public License version 2.
 *
 * This header defines the 64-bit dispatch queue (DSQ) ID encoding
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
 *   [ 0][   unused   ] [ VAL ]
 *
 *   Mitosis uses VAL as follows:
 *
 *   [31..28] [27..0]
 *   [QTYPE ] [DATA ]
 *
 *   QTYPE encodes the queue type:
 *
 *     QTYPE = 0x1 -> Per-CPU Q
 *       [31..28] [27 ..          ..        0]
 *       [ 0001 ] [          CPU#            ]
 *       [Q-TYPE:1]
 *
 *     QTYPE = 0x2 -> Cell+L3 Q
 *       [31..28] [27 .. 16] [15      ..    0]
 *       [ 0010 ] [  CELL# ] [      L3ID     ]
 *       [Q-TYPE:2]
 *
 */
/*
 * The use of these bitfields depends on compiler defined byte AND bit ordering.
 * Make sure we're only building with Clang/LLVM and that we're little-endian.
 */
#ifndef __clang__
#error "This code must be compiled with Clang/LLVM (eBPF: clang -target bpf)."
#endif

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "dsq64 bitfield layout assumes little-endian (bpfel)."
#endif

/* ---- Bitfield widths (bits) ---- */
#define CPU_B 28
#define L3_B 16
#define CELL_B 12
#define TYPE_B 4
#define DATA_B 28
#define RSVD_B 32

/* Sum checks (in bits) */
_Static_assert(CPU_B + TYPE_B == 32, "CPU layout low half must be 32 bits");
_Static_assert(L3_B + CELL_B + TYPE_B == 32,
	       "CELL+L3 layout low half must be 32 bits");
_Static_assert(DATA_B + TYPE_B == 32, "Common layout low half must be 32 bits");

typedef union {
	u64 raw;

	/* Per-CPU user DSQ */
	struct {
		u64 cpu : CPU_B;
		u64 type : TYPE_B;
		u64 rsvd : RSVD_B;
	} cpu_dsq;

	/* Cell+L3 user DSQ */
	struct {
		u64 l3 : L3_B;
		u64 cell : CELL_B;
		u64 type : TYPE_B;
		u64 rsvd : RSVD_B;
	} cell_l3_dsq;

	/* Generic user view */
	struct {
		u64 data : DATA_B;
		u64 type : TYPE_B;
		u64 rsvd : RSVD_B;
	} user_dsq;

	/* Built-in DSQ view */
	struct {
		u64 value : 32;
		u64 rsvd : 30;
		u64 local_on : 1;
		u64 builtin : 1;
	} builtin_dsq;

	/* NOTE: Considered packed and aligned attributes, but that's redundant */
} dsq_id_t;

/*
 * Invalid DSQ ID Sentinel:
 * invalid bc bit 63 clear (it's a user DSQ) && dsq_type == 0 (no type)
 * Good for catching uninitialized DSQ IDs.
*/
#define DSQ_INVALID ((u64)0)

_Static_assert(sizeof(((dsq_id_t){ 0 }).cpu_dsq) == sizeof(u64),
	       "cpu view must be 8 bytes");
_Static_assert(sizeof(((dsq_id_t){ 0 }).cell_l3_dsq) == sizeof(u64),
	       "cell+l3 view must be 8 bytes");
_Static_assert(sizeof(((dsq_id_t){ 0 }).user_dsq) == sizeof(u64),
	       "user common view must be 8 bytes");
_Static_assert(sizeof(((dsq_id_t){ 0 }).builtin_dsq) == sizeof(u64),
	       "builtin view must be 8 bytes");

/* Compile-time checks (in bytes) */
_Static_assert(sizeof(dsq_id_t) == sizeof(u64),
	       "dsq_id_t must be 8 bytes (64 bits)");
_Static_assert(_Alignof(dsq_id_t) == sizeof(u64),
	       "dsq_id_t must be 8-byte aligned");

/* DSQ type enumeration */
enum dsq_type {
	DSQ_TYPE_NONE,
	DSQ_TYPE_CPU,
	DSQ_TYPE_CELL_L3,
};

/* Range guards */
_Static_assert(MAX_CPUS <= (1u << CPU_B), "MAX_CPUS must fit in field");
_Static_assert(MAX_L3S <= (1u << L3_B), "MAX_L3S must fit in field");
_Static_assert(MAX_CELLS <= (1u << CELL_B), "MAX_CELLS must fit in field");
_Static_assert(DSQ_TYPE_CELL_L3 < (1u << TYPE_B),
	       "DSQ_TYPE_CELL_L3 must fit in field");

/*
 * While I considered error propagation, I decided to bail to force errors early.
*/

static inline bool is_user_dsq(dsq_id_t dsq_id)
{
	return !dsq_id.builtin_dsq.builtin &&
	       dsq_id.user_dsq.type != DSQ_TYPE_NONE;
}

// Is this a per CPU DSQ?
static inline bool is_cpu_dsq(dsq_id_t dsq_id)
{
	return is_user_dsq(dsq_id) && dsq_id.user_dsq.type == DSQ_TYPE_CPU;
}

// If this is a per cpu dsq, return the cpu
static inline u32 get_cpu_from_dsq(dsq_id_t dsq_id)
{
	if (!is_cpu_dsq(dsq_id))
		scx_bpf_error("trying to get cpu from non-cpu dsq\n");

	return dsq_id.cpu_dsq.cpu;
}

/* Helper functions to construct DSQ IDs */
static inline dsq_id_t get_cpu_dsq_id(u32 cpu)
{
	// Check for valid CPU range, 0 indexed so >=.
	if (cpu >= MAX_CPUS)
		scx_bpf_error("invalid cpu %u\n", cpu);

	return (dsq_id_t){ .cpu_dsq = { .cpu = cpu, .type = DSQ_TYPE_CPU } };
}

static inline dsq_id_t get_cell_l3_dsq_id(u32 cell, u32 l3)
{
	if (cell >= MAX_CELLS || l3 >= MAX_L3S)
		scx_bpf_error("cell %u or l3 %u too large\n", cell, l3);

	return (dsq_id_t){ .cell_l3_dsq = { .l3 = l3,
					    .cell = cell,
					    .type = DSQ_TYPE_CELL_L3 } };
}
