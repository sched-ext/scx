/*
 * sim_wrapper.h - Wrapper header for compiling BPF schedulers as userspace C
 *
 * This header must be included BEFORE the scheduler's .bpf.c file.
 * It sets up the test infrastructure from lib/scxtest/, includes
 * common.bpf.h (to set its header guard), then overrides BPF macros
 * to produce regular C functions callable from the simulator.
 */
#pragma once

/* Pull in the unit test infrastructure (overrides, map emulation, cpumask) */
#include <scx_test.h>
#include <scx_test_map.h>
#include <scx_test_cpumask.h>

/* Include common.bpf.h to get type definitions and set the header guard.
 * When the scheduler .bpf.c re-includes it, it will be skipped. */
#include <scx/common.bpf.h>

/*
 * Undo BPF CO-RE enum variable macros from enums.autogen.bpf.h.
 *
 * In BPF programs, these constants are resolved at load time via CO-RE
 * relocation. enums.autogen.bpf.h redefines each SCX_* enum constant as
 * a weak variable (__SCX_*) which the BPF loader patches. In userspace,
 * these weak variables default to 0 — breaking the scheduler logic.
 *
 * By undefining the macros, the compiler falls back to the real enum
 * values from vmlinux.h.
 */
#undef SCX_OPS_NAME_LEN
#undef SCX_SLICE_DFL
#undef SCX_SLICE_INF
#undef SCX_RQ_ONLINE
#undef SCX_RQ_CAN_STOP_TICK
#undef SCX_RQ_BAL_PENDING
#undef SCX_RQ_BAL_KEEP
#undef SCX_RQ_BYPASSING
#undef SCX_RQ_CLK_VALID
#undef SCX_RQ_IN_WAKEUP
#undef SCX_RQ_IN_BALANCE
#undef SCX_DSQ_FLAG_BUILTIN
#undef SCX_DSQ_FLAG_LOCAL_ON
#undef SCX_DSQ_INVALID
#undef SCX_DSQ_GLOBAL
#undef SCX_DSQ_LOCAL
#undef SCX_DSQ_LOCAL_ON
#undef SCX_DSQ_LOCAL_CPU_MASK
#undef SCX_TASK_QUEUED
#undef SCX_TASK_RESET_RUNNABLE_AT
#undef SCX_TASK_DEQD_FOR_SLEEP
#undef SCX_TASK_STATE_SHIFT
#undef SCX_TASK_STATE_BITS
#undef SCX_TASK_STATE_MASK
#undef SCX_TASK_CURSOR
#undef SCX_TASK_NONE
#undef SCX_TASK_INIT
#undef SCX_TASK_READY
#undef SCX_TASK_ENABLED
#undef SCX_TASK_NR_STATES
#undef SCX_TASK_DSQ_ON_PRIQ
#undef SCX_KICK_IDLE
#undef SCX_KICK_PREEMPT
#undef SCX_KICK_WAIT
#undef SCX_ENQ_WAKEUP
#undef SCX_ENQ_HEAD
#undef SCX_ENQ_PREEMPT
#undef SCX_ENQ_REENQ
#undef SCX_ENQ_LAST
#undef SCX_ENQ_CLEAR_OPSS
#undef SCX_ENQ_DSQ_PRIQ

/*
 * Undo compat macros from compat.bpf.h.
 *
 * compat.bpf.h wraps kfunc calls like scx_bpf_dsq_insert() with
 * bpf_ksym_exists() ternary expressions that fall back to ___compat
 * variants for older kernels. In the simulator, we provide the kfuncs
 * directly as #[no_mangle] Rust functions — no compat indirection needed.
 */
#undef scx_bpf_dsq_insert
#undef scx_bpf_dsq_insert_vtime
#undef scx_bpf_dsq_move_to_local
#undef scx_bpf_now

/*
 * Override BPF_STRUCT_OPS to produce regular C functions.
 * In BPF mode, BPF_STRUCT_OPS wraps functions with SEC annotations and
 * BPF_PROG argument unpacking. In simulator mode, we just want plain
 * C functions with typed arguments.
 */
#undef BPF_STRUCT_OPS
#define BPF_STRUCT_OPS(name, args...) \
    __attribute__((used)) name(args)

#undef BPF_STRUCT_OPS_SLEEPABLE
#define BPF_STRUCT_OPS_SLEEPABLE(name, args...) \
    __attribute__((used)) name(args)

/* SCX_OPS_DEFINE creates a struct_ops registration - not needed in simulator */
#undef SCX_OPS_DEFINE
#define SCX_OPS_DEFINE(name, ...)

/*
 * Stub out BPF helpers used by UEI_RECORD and other kernel-only code paths.
 * These are BPF helpers that don't exist in userspace.
 */
#ifndef bpf_probe_read_kernel_str
#define bpf_probe_read_kernel_str(dst, sz, src) ((void)(dst), (void)(sz), (void)(src), (long)0)
#endif

/* __kconfig variables don't exist in userspace */
#undef __kconfig
#define __kconfig

