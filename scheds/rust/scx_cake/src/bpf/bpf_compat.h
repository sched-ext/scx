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

/* Bitfield extraction: shift + mask (2 cycles) — BMI2 BEXTR unavailable in BPF ISA */
#define EXTRACT_BITS_U32(val, start, len) \
    (((u32)(val) >> (start)) & ((1U << (len)) - 1))
#define EXTRACT_BITS_U64(val, start, len) \
    (((u64)(val) >> (start)) & ((1ULL << (len)) - 1))



/* ═══════════════════════════════════════════════════════════════════════════
 * PREFETCH: Materialize address early to encourage prefetch-like behavior
 * - Forces compiler to compute the address, enabling earlier load scheduling
 * - No "memory" clobber: avoids acting as a compiler barrier that would
 *   flush store buffers and inhibit register caching / ILP / MLP
 * ═══════════════════════════════════════════════════════════════════════════ */
#define CAKE_PREFETCH(addr) \
    asm volatile("" : : "r"(addr))



/* ═══════════════════════════════════════════════════════════════════════════
 * RQ ACCESS: Prefer scx_bpf_locked_rq() over deprecated scx_bpf_cpu_rq().
 *
 * scx_bpf_locked_rq(): ~3-5ns (no RCU, no bounds check, rq lock held)
 * scx_bpf_cpu_rq():    ~10-15ns (RCU + bounds check, deprecated)
 *
 * cake_tick holds the local rq lock, so locked_rq is both faster and correct.
 * Declared __weak: if kernel doesn't export it, falls back to cpu_rq.
 * ═══════════════════════════════════════════════════════════════════════════ */
extern struct rq *scx_bpf_locked_rq(void) __weak __ksym;

static __always_inline struct rq *cake_get_rq(s32 cpu) {
    if (scx_bpf_locked_rq)
        return scx_bpf_locked_rq();
    return scx_bpf_cpu_rq(cpu);
}

#endif /* __CAKE_BPF_COMPAT_H */
