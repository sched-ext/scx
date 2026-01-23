/* scx_cake/bpf/bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/*
 * COMPILER ABSTRACTION: Optimized Atomic Access
 * ---------------------------------------------------------------------------
 * Clang 21+: Uses formal atomics for Alias Analysis + MLP (Memory Level
 *            Parallelism). The compiler can interleave unrelated math between
 *            memory loads, hiding latency.
 * Clang <21: Scalpel-Optimized ASM to bypass Clang 19 GVN/OOM bugs.
 *            Uses targeted "m" constraints instead of global "memory" clobber
 *            to prevent unnecessary register spills on hot paths.
 * ---------------------------------------------------------------------------
 */

#if defined(__clang__) && __clang_major__ >= 21

    /* MODERN PATH: Formal Atomics (Max Performance) */
    #define cake_relaxed_load_u32(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u32(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)
    #define cake_relaxed_load_u64(ptr)      __atomic_load_n(ptr, __ATOMIC_RELAXED)
    #define cake_relaxed_store_u64(ptr, v)  __atomic_store_n(ptr, v, __ATOMIC_RELAXED)

#else

    /* COMPAT PATH: Scalpel-Optimized Inline Assembly */

    static __always_inline u32 cake_relaxed_load_u32(const volatile u32 *ptr) {
        u32 val;
        asm volatile(
            "%0 = *(u32 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)  /* Targeted dependency, no global spill */
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u32(volatile u32 *ptr, u32 val) {
        asm volatile(
            "*(u32 *)(%1 + 0) = %2"
            : "=m"(*ptr)           /* Only this address modified */
            : "r"(ptr), "r"(val)
        );
    }

    static __always_inline u64 cake_relaxed_load_u64(const volatile u64 *ptr) {
        u64 val;
        asm volatile(
            "%0 = *(u64 *)(%1 + 0)"
            : "=r"(val)
            : "r"(ptr), "m"(*ptr)
        );
        return val;
    }

    static __always_inline void cake_relaxed_store_u64(volatile u64 *ptr, u64 val) {
        asm volatile(
            "*(u64 *)(%1 + 0) = %2"
            : "=m"(*ptr)
            : "r"(ptr), "r"(val)
        );
    }

#endif

/*
 * BPF ISA ATOMIC TARGETING
 * ---------------------------------------------------------------------------
 * Map to BPF_ATOMIC_OR/AND instructions by using __atomic built-ins with
 * a void cast. This avoids the overhead of the 'fetch' variant (extra regs)
 * and ensures the JIT emits a single LOCK OR/AND on x86_64.
 * ---------------------------------------------------------------------------
 */
#define bpf_atomic_or(ptr, val) \
    ((void)__atomic_fetch_or((ptr), (val), __ATOMIC_RELAXED))

#define bpf_atomic_and(ptr, val) \
    ((void)__atomic_fetch_and((ptr), (val), __ATOMIC_RELAXED))

/*
 * BMI2 BEXTR: Extract bitfield in 1 cycle
 * Fallback: Shift + mask (2 cycles)
 */
#if defined(__BMI2__) && defined(__x86_64__)
    #define EXTRACT_BITS_U32(val, start, len) \
        __builtin_ia32_bextr_u32((val), ((len) << 8) | (start))
    #define EXTRACT_BITS_U64(val, start, len) \
        __builtin_ia32_bextr_u64((val), ((len) << 8) | (start))
#else
    #define EXTRACT_BITS_U32(val, start, len) \
        (((u32)(val) >> (start)) & ((1U << (len)) - 1))
    #define EXTRACT_BITS_U64(val, start, len) \
        (((u64)(val) >> (start)) & ((1ULL << (len)) - 1))
#endif

/*
 * BIT SCAN FORWARD (CTZ): Deterministic bit scanning
 * Note: BPF ISA does not have a native bit-scan instruction.
 * __builtin_ctzll lowers to an efficient De Bruijn sequence in Clang/LLVM.
 */
#define BIT_SCAN_FORWARD_U64(mask) __builtin_ctzll(mask)

/*
 * RAW BIT SCAN: Allows passing a pre-hoisted multiplier
 */
#define BIT_SCAN_FORWARD_U64_RAW(mask, mult) ((u8)((mult * ((mask) & -(mask))) >> 58))

#endif /* __CAKE_BPF_COMPAT_H */
