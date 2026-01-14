/* scx_cake/bpf/bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/*
 * COMPILER ABSTRACTION: 32-bit/64-bit Atomic Access
 * ---------------------------------------------------------------------------
 * Issue: Clang 19's BPF backend hangs or crashes on complex volatile loads,
 * causing CI failures (Exit 143/OOM) or build errors.
 *
 * Fix:   1. Clang 21+: Use formal atomics for maximum optimization (MLP).
 *        2. Clang <21: Use Inline ASM to force raw BPF instructions,
 *           bypassing the broken compiler analysis phase.
 * ---------------------------------------------------------------------------
 */

#if defined(__clang__) && __clang_major__ >= 21

    /* MODERN PATH: Formal Atomics (Optimized/MLP) */
    #define cake_relaxed_load_u32(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u32(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
    #define cake_relaxed_load_u64(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u64(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)

#else

    /* COMPAT PATH: Inline Assembly (Bypasses Compiler OOM/Hang) */
    
    static __always_inline u32 cake_relaxed_load_u32(volatile u32 *ptr) {
        u32 val;
        /* Raw BPF load: rX = *(u32 *)(rY + 0) */
        asm volatile(
            "%0 = *(u32 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr)
            : "memory"
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u32(volatile u32 *ptr, u32 val) {
        /* Raw BPF store: *(u32 *)(rX + 0) = rY */
        asm volatile(
            "*(u32 *)(%0 + 0) = %1"
            :
            : "r"(ptr), "r"(val)
            : "memory"
        );
    }

    static __always_inline u64 cake_relaxed_load_u64(volatile u64 *ptr) {
        u64 val;
        /* Raw BPF load: rX = *(u64 *)(rY + 0) */
        asm volatile(
            "%0 = *(u64 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr)
            : "memory"
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u64(volatile u64 *ptr, u64 val) {
        /* Raw BPF store: *(u64 *)(rX + 0) = rY */
        asm volatile(
            "*(u64 *)(%0 + 0) = %1"
            :
            : "r"(ptr), "r"(val)
            : "memory"
        );
    }

#endif

#endif /* __CAKE_BPF_COMPAT_H */
