/* bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/* -------------------------------------------------------------------------
 * COMPILER WORKAROUND: Clang 19 BPF Backend Defect
 * -------------------------------------------------------------------------
 * Issue: Clang 19 fails to select instructions for 32-bit formal atomics 
 * (__atomic_load_n) in the BPF backend, causing a build crash.
 * Fix:   Downgrade to volatile access (READ_ONCE) for Clang < 21.
 * Volatile loads on aligned 32-bit data are implicitly atomic 
 * on BPF/x86 (single-copy atomicity).
 * -------------------------------------------------------------------------
 */

/* Ensure READ_ONCE/WRITE_ONCE exist (if not provided by vmlinux.h) */
#ifndef READ_ONCE
#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#endif

#ifndef WRITE_ONCE
#define WRITE_ONCE(x, val) (*(volatile typeof(x) *)&(x) = (val))
#endif

/* Define semantic macros based on compiler capability.
 * Use Clang 21 as the cutoff for safely re-enabling formal atomics.
 */
#if defined(__clang__) && __clang_major__ >= 21
    /* Modern Path: Formal Atomics (Enable MLP/optimization) */
    #define cake_relaxed_load_u32(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u32(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
    #define cake_relaxed_load_u64(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u64(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
#else
    /* Legacy/Compat Path: Volatile Fallback (Prevents Crash) */
    #define cake_relaxed_load_u32(ptr)      READ_ONCE(*(ptr))
    #define cake_relaxed_store_u32(ptr, v)  WRITE_ONCE(*(ptr), (v))
    #define cake_relaxed_load_u64(ptr)      READ_ONCE(*(ptr))
    #define cake_relaxed_store_u64(ptr, v)  WRITE_ONCE(*(ptr), (v))
#endif

#endif /* __CAKE_BPF_COMPAT_H */
