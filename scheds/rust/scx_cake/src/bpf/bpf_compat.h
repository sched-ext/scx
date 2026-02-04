/* scx_cake/bpf/bpf_compat.h */
#ifndef __CAKE_BPF_COMPAT_H
#define __CAKE_BPF_COMPAT_H

/* Compiler abstraction: Clang 21+ uses formal atomics for MLP; <21 uses scalpel-optimized ASM */

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

/* BPF atomic targeting - maps to BPF_ATOMIC_OR/AND via void-cast fetch variants (single LOCK OR/AND) */
#define bpf_atomic_or(ptr, val) \
    ((void)__atomic_fetch_or((ptr), (val), __ATOMIC_RELAXED))

#define bpf_atomic_and(ptr, val) \
    ((void)__atomic_fetch_and((ptr), (val), __ATOMIC_RELAXED))

/* BMI2 BEXTR: Extract bitfield in 1 cycle; fallback: shift + mask (2 cycles) */
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

/* BIT SCAN FORWARD (CTZ): Clang <19 fallback uses De Bruijn to avoid opcode 191 crash */
#if defined(__clang__) && __clang_major__ < 19
    static __always_inline u32 cake_ctz64(u64 mask, u64 mult) {
        static const u8 de_bruijn_bits[64] = {
            0,  1,  2, 53,  3,  7, 54, 27, 4, 38, 41,  8, 34, 55, 48, 28,
            62, 5, 39, 46, 44, 42, 22,  9, 24, 35, 59, 56, 49, 18, 29, 11,
            63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
            51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
        };

        u64 lsb = mask & -mask;

        /* Obfuscation barrier: prevents Clang 18 from optimizing back to __builtin_ctzll */
        asm volatile("" : "+r"(lsb));

        return de_bruijn_bits[(lsb * mult) >> 58];
    }
    #define BIT_SCAN_FORWARD_U64(mask) cake_ctz64(mask, 0x022FDD63CC95386DULL)
    #define BIT_SCAN_FORWARD_U64_RAW(mask, mult) cake_ctz64(mask, mult)
#else
    #define BIT_SCAN_FORWARD_U64(mask) __builtin_ctzll(mask)
    #define BIT_SCAN_FORWARD_U64_RAW(mask, mult) __builtin_ctzll(mask)
#endif

/* ═══════════════════════════════════════════════════════════════════════════
 * PREFETCH: Issue async memory prefetch to hide DDR5 latency (~100ns)
 * - Must be issued 500+ cycles before read for full benefit
 * - No-op if prefetch fails; graceful degradation to cold read
 * ═══════════════════════════════════════════════════════════════════════════ */
#define CAKE_PREFETCH(addr) \
    asm volatile("" : : "r"(addr) : "memory")
/* Note: BPF doesn't support actual prefetch instructions (prefetcht0/prefetchnta).
 * This asm volatile creates a data dependency that encourages the compiler to
 * load the address early, providing some prefetch-like behavior. For full DRAM
 * prefetch, the kernel would need to expose a BPF helper. */

/* DSQ peek compat - v6.19+ uses native, older kernels use noinline iterator fallback */
/* Prototype for scratch-tunneled version in cake.bpf.c */
struct task_struct *cake_bpf_dsq_peek_legacy(u64 dsq_id);

static __always_inline struct task_struct *cake_bpf_dsq_peek(u64 dsq_id) {
    if (bpf_ksym_exists(scx_bpf_dsq_peek))
        return scx_bpf_dsq_peek(dsq_id);
    return cake_bpf_dsq_peek_legacy(dsq_id);
}

#endif /* __CAKE_BPF_COMPAT_H */
