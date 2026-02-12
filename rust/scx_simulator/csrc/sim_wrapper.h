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
 * UEI_DEFINE produces global symbols (uei, uei_dump, uei_dump_len) that
 * collide when multiple schedulers are linked into the same binary.
 * Override to produce weak symbols so the linker picks one arbitrarily.
 */
#undef UEI_DEFINE
#define UEI_DEFINE(__name) \
    __attribute__((weak)) char __name##_dump[4096]; \
    __attribute__((weak)) const volatile u32 __name##_dump_len; \
    __attribute__((weak)) struct user_exit_info __name

/*
 * Override SEC("license") to produce weak symbols.
 * Multiple schedulers define `char _license[] SEC("license") = "GPL"`.
 * We strip the section attribute (not meaningful in userspace) and add weak.
 */
#undef SEC
#define SEC(name) __attribute__((weak))

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

/*
 * BPF iterator overrides.
 *
 * bpf_for_each(scx_dsq, ...) iterates tasks in a DSQ — not yet supported
 * in the simulator. The loop body compiles but never executes.
 *
 * bpf_for(i, start, end) is a bounded loop helper — maps to a plain for loop.
 */
#undef bpf_for_each
#define bpf_for_each(type, cur, args...) while (0)

#undef bpf_for
#define bpf_for(i, start, end) for ((i) = (start); (i) < (end); (i)++)

/*
 * Compat macro overrides for functions that depend on dead-code-eliminated
 * iterator paths (bpf_for_each body is unreachable with the above stub).
 */
#undef __COMPAT_scx_bpf_dsq_move
#define __COMPAT_scx_bpf_dsq_move(it, p, dsq_id, enq_flags) false

#undef __COMPAT_scx_bpf_cpu_curr
#define __COMPAT_scx_bpf_cpu_curr(cpu) ((struct task_struct *)NULL)

/*
 * BPF timer overrides.
 *
 * In BPF, bpf_timer_* are helper function pointers defined in
 * bpf_helper_defs.h. In the simulator, timers are not modeled,
 * so we stub them out as no-op macros before the BPF headers
 * are included.
 */
#undef bpf_timer_init
#define bpf_timer_init(timer, map, flags) (0)
#undef bpf_timer_set_callback
#define bpf_timer_set_callback(timer, cb) (0)
#undef bpf_timer_start
#define bpf_timer_start(timer, nsecs, flags) (0)

/*
 * bpf_kptr_xchg override.
 *
 * In BPF, bpf_kptr_xchg is a static function pointer set to (void *)194.
 * In the simulator, we route it to our bpf_kptr_xchg_impl stub which
 * does a simple pointer swap.
 */
extern void *bpf_kptr_xchg_impl(void **kptr, void *new_val);
#undef bpf_kptr_xchg
#define bpf_kptr_xchg(kptr, new_val) bpf_kptr_xchg_impl((void **)(kptr), (void *)(new_val))

/*
 * bpf_get_smp_processor_id override.
 *
 * In BPF, this returns the current CPU ID via a helper at (void *)8.
 * In the simulator, we route it to our kfunc that reads current_cpu
 * from the simulator state.
 */
extern unsigned int sim_bpf_get_smp_processor_id(void);
#undef bpf_get_smp_processor_id
#define bpf_get_smp_processor_id() sim_bpf_get_smp_processor_id()

/*
 * bpf_get_current_task_btf override.
 *
 * In BPF, this is a helper at (void *)158. In the simulator, it routes
 * to our Rust kfunc that returns the current CPU's running task.
 */
extern struct task_struct *sim_bpf_get_current_task_btf(void);
#undef bpf_get_current_task_btf
#define bpf_get_current_task_btf() sim_bpf_get_current_task_btf()

