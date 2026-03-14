# BPF Trusted Pointer Analysis for Rust/aya struct_ops Programs

Date: 2026-03-14
Status: Research complete, findings contradict original assumption

## Executive Summary

The original assumption -- that the BPF verifier "consumes" trusted pointer
status after kfunc calls, making it impossible to call multiple kfuncs with the
same `task_struct *p` -- is **incorrect for non-KF_RELEASE kfuncs**. Kernel
source analysis (v6.16) shows that:

1. Callee-saved registers (R6-R9) retain their full type info including
   `PTR_TRUSTED` across kfunc calls
2. The relevant scx kfuncs (`scx_bpf_task_cpu`, `scx_bpf_task_running`,
   `scx_bpf_dsq_insert`) are flagged `KF_RCU`, NOT `KF_RELEASE`
3. Only `KF_RELEASE` kfuncs invalidate all copies of a pointer
4. The Rust/LLVM compiler already uses callee-saved registers correctly

The migration pattern in `cosmos_enqueue` should work without workarounds.

---

## 1. How the BPF Verifier Tracks Pointer Trust

### Register State Model

The verifier maintains a `bpf_reg_state` for each register (R0-R10) and stack
slot. For pointers, the key fields are:

- `type`: base type (e.g., `PTR_TO_BTF_ID`) plus modifier flags
  (e.g., `PTR_TRUSTED`, `PTR_UNTRUSTED`, `MEM_RCU`, `PTR_MAYBE_NULL`)
- `btf_id`: the BTF type ID of the pointed-to struct
- `ref_obj_id`: non-zero for reference-counted (acquired) pointers

### What Makes a Pointer "Trusted"

From `kernel/bpf/verifier.c`, the `is_trusted_reg()` function:

```c
static bool is_trusted_reg(const struct bpf_reg_state *reg)
{
    /* A referenced register is always trusted. */
    if (reg->ref_obj_id)
        return true;

    /* Types listed in reg2btf_ids are always trusted */
    if (reg2btf_ids[base_type(reg->type)] &&
        !bpf_type_has_unsafe_modifiers(reg->type))
        return true;

    /* PTR_TRUSTED or MEM_ALLOC, with no unsafe modifiers */
    return type_flag(reg->type) & BPF_REG_TRUSTED_MODIFIERS &&
           !bpf_type_has_unsafe_modifiers(reg->type);
}
```

Trust is determined by:
1. Having a non-zero `ref_obj_id` (acquired pointer), OR
2. Being a well-known type (PTR_TO_SOCKET, etc.), OR
3. Having the `PTR_TRUSTED` type flag without unsafe modifiers

### How struct_ops Arguments Get PTR_TRUSTED

From `kernel/bpf/btf.c`, `btf_ctx_access()` line 6811-6813:

```c
info->reg_type = PTR_TO_BTF_ID;
if (prog_args_trusted(prog))
    info->reg_type |= PTR_TRUSTED;
```

And `prog_args_trusted()` line 6437-6438:

```c
case BPF_PROG_TYPE_STRUCT_OPS:
    return true;
```

So struct_ops callback arguments are `PTR_TO_BTF_ID | PTR_TRUSTED` with
`ref_obj_id = 0`. They are trusted by virtue of the PTR_TRUSTED flag, not
by reference counting.

---

## 2. What Happens After a Kfunc Call

### Register Clearing (ALL kfunc calls)

From `check_kfunc_call()` in `verifier.c` line 14019-14020:

```c
for (i = 0; i < CALLER_SAVED_REGS; i++)
    mark_reg_not_init(env, regs, caller_saved[i]);
```

Where `caller_saved = { BPF_REG_0, BPF_REG_1, ..., BPF_REG_5 }`.

**Only R0-R5 are cleared.** R6-R9 are callee-saved and retain their complete
type information, including `PTR_TRUSTED`.

### KF_RELEASE-specific Invalidation (ONLY for release kfuncs)

From `release_reference()` in `verifier.c` line 10322-10339:

```c
static int release_reference(struct bpf_verifier_env *env, int ref_obj_id)
{
    ...
    bpf_for_each_reg_in_vstate(vstate, state, reg, ({
        if (reg->ref_obj_id == ref_obj_id)
            mark_reg_invalid(env, reg);
    }));
    return 0;
}
```

This walks ALL registers (including R6-R9) and ALL stack slots, invalidating
every register that holds a copy of the released pointer (matched by
`ref_obj_id`). This is why the docs say "all copies of the pointer being
released are invalidated."

**Crucially:** struct_ops callback arguments have `ref_obj_id = 0`, so they
would not be matched by this sweep even if a KF_RELEASE kfunc were called.
However, the KF_RELEASE kfuncs require a non-zero `ref_obj_id` on their
argument anyway, so this scenario doesn't arise.

---

## 3. The scx Kfunc Flags

From `kernel/sched/ext.c` BTF_ID_FLAGS registration:

| Kfunc                          | Flags          | Releases? |
|--------------------------------|----------------|-----------|
| `scx_bpf_dsq_insert`          | `KF_RCU`       | No        |
| `scx_bpf_dsq_insert_vtime`    | `KF_RCU`       | No        |
| `scx_bpf_task_running`        | `KF_RCU`       | No        |
| `scx_bpf_task_cpu`            | `KF_RCU`       | No        |
| `scx_bpf_select_cpu_dfl`      | (default)      | No        |
| `scx_bpf_kick_cpu`            | (default)      | No        |
| `scx_bpf_now`                 | (default)      | No        |
| `scx_bpf_cpuperf_set`         | (default)      | No        |
| `scx_bpf_put_cpumask`         | `KF_RELEASE`   | **Yes**   |
| `scx_bpf_get_idle_cpumask`    | `KF_ACQUIRE`   | No        |
| `scx_bpf_get_possible_cpumask`| `KF_ACQUIRE`   | No        |

`KF_RCU` means "accepts either trusted or RCU-protected pointers." From the
verifier argument check code (line 13198-13210):

```c
if (!is_kfunc_trusted_args(meta) && !is_kfunc_rcu(meta))
    break;

if (!is_trusted_reg(reg)) {
    if (!is_kfunc_rcu(meta)) {
        verbose(env, "R%d must be referenced or trusted\n", regno);
        return -EINVAL;
    }
    if (!is_rcu_reg(reg)) {
        verbose(env, "R%d must be a rcu pointer\n", regno);
        return -EINVAL;
    }
}
```

Since `PTR_TRUSTED` pointers pass `is_trusted_reg()`, they are accepted by
`KF_RCU` kfuncs. And since none of these kfuncs are `KF_RELEASE`, the trusted
pointer in a callee-saved register is NOT invalidated after the call.

---

## 4. What the Rust Compiler Actually Generates

Examining the compiled BPF bytecode (from `scx_cosmos`), the LLVM BPF backend
correctly uses callee-saved registers. For example, in `select_cpu`:

```
r6 = *(u64 *)(r1 + 0x0)    ; load p into R6 (callee-saved)
...
r1 = r6                     ; copy p to R1 for first kfunc
call -0x1                   ; select_cpu_dfl(p, ...)
...
r1 = r6                     ; copy p back to R1 for second kfunc
call -0x1                   ; dsq_insert(p, ...)
```

The inline asm kfunc wrappers correctly declare R0-R5 as clobbered but NOT
R6-R9, so LLVM knows it can keep `p` in a callee-saved register across calls.

**The Rust compiler does NOT have a deficiency here.** It generates the same
pattern as clang: save the pointer in R6-R9, restore to R1 before each call.

---

## 5. How Clang "Re-derives" Trusted Pointers (Revisited)

The original question assumed clang does something special to "re-derive"
trusted pointers. The answer is simpler: **it doesn't need to.** The BPF
calling convention preserves R6-R9 across calls, and the verifier preserves
their type state (including PTR_TRUSTED). Both clang and rustc/LLVM use
callee-saved registers to hold pointers across calls.

There is no special LLVM pass, no BPF-specific annotation, and no instruction
sequence for "trust re-derivation." The mechanism is simply:

1. Save pointer in R6 before call (`r6 = r1` or `r6 = *(u64 *)(r1 + off)`)
2. Call kfunc (clears R0-R5, preserves R6-R9)
3. Restore pointer from R6 (`r1 = r6`)
4. Call next kfunc

---

## 6. Why the Problem Was Misdiagnosed

The likely causes of the original misdiagnosis:

### a. Confusion with KF_RELEASE kfuncs

`scx_bpf_put_cpumask` IS `KF_RELEASE` and DOES invalidate all copies of the
released pointer. If early experiments involved acquire/release patterns (e.g.,
`get_idle_cpumask` / `put_cpumask`), the observed pointer invalidation would
have been from the release kfunc, not from general kfunc calls.

### b. Stack spill issues

If the compiler spills the pointer to the stack instead of keeping it in a
callee-saved register, AND a helper writes to that stack region, the verifier
would invalidate the spilled pointer. This could happen with complex Rust code
that exhausts callee-saved registers (only R6-R9 are available, and R10 is the
frame pointer).

### c. bpf_probe_read_kernel invalidation

The `core_read!` macro calls `bpf_probe_read_kernel` (helper 0x71), which takes
`ARG_PTR_TO_MEM` as its first argument. If the verifier considers this as
writing to the output buffer on the stack, it might invalidate any spilled
pointers in the affected memory range. This is documented behavior: helpers that
write to stack memory clobber spilled pointer references.

### d. Type demotion through pointer arithmetic

If the code adds an offset to a trusted pointer (e.g., `p + 0x390` to access
`scx.dsq_vtime`), the result loses `PTR_TRUSTED` status. The verifier
documentation states: "pointers obtained from walking PTR_TRUSTED pointers are
not trusted." Direct field access (pointer + offset) is permitted for reading,
but the resulting register is not trusted for kfunc argument purposes.

---

## 7. Solution Assessment

### a. LLVM Plugin Pass -- NOT NEEDED

The original suggestion of an LLVM plugin pass to insert "trust re-derivation"
instructions is unnecessary. The compiler already generates correct code. The
verifier already preserves trust in callee-saved registers.

### b. Post-processor ELF Patching -- NOT NEEDED

No bytecode patching is required. The instruction sequence is correct.

### c. BPF Subprogram Boundaries -- NOT NEEDED (but useful for other reasons)

`#[inline(never)]` does work for the BPF target (LLVM supports it). The
verifier handles BPF-to-BPF calls by creating a new frame and validating
argument types. However, for the trusted pointer issue, this is not needed.

Subprograms could be useful if callee-saved register pressure becomes a problem
(complex functions needing more than 4 live values across calls), but this is
an optimization concern, not a trust concern.

### d. bpf_rcu_read_lock -- PARTIALLY RELEVANT

`bpf_rcu_read_lock()` creates an RCU read-side critical section. Pointers
accessed within this section can have `MEM_RCU` flag, which is accepted by
`KF_RCU` kfuncs. However, since struct_ops arguments already have
`PTR_TRUSTED`, this is unnecessary for the basic case.

`bpf_rcu_read_lock` becomes relevant if you need to walk a trusted pointer to
reach a nested pointer (e.g., `p->se.cfs_rq->tg`) -- the walked pointer loses
`PTR_TRUSTED` but could gain `MEM_RCU` within an RCU critical section.

### e. Wrapper kfuncs -- NOT NEEDED

Custom kernel module kfuncs are not needed for this case.

### f. ACTUAL SOLUTION: Just do it

The migration pattern (`task_cpu` + `task_running` + `dsq_insert` on the same
`p`) should work directly. The inline asm kfunc wrappers already handle the
calling convention correctly. The verifier preserves trust in callee-saved
registers.

**Recommended approach:**
1. Simply call `kfuncs::task_cpu(p)`, then `kfuncs::task_running(p)`, then
   `kfuncs::dsq_insert(p, ...)` in sequence
2. The compiler will keep `p` in a callee-saved register
3. Verify by loading the program and checking the verifier log

If verification fails despite the correct bytecode, the most likely cause would
be register pressure forcing a stack spill. In that case:
- Simplify the function to reduce live values across calls
- Use `#[inline(never)]` subprograms to isolate register-heavy sections
- As a last resort, use `bpf_rcu_read_lock` for RCU-based trust

---

## 8. Verifier Register State Quick Reference

| Register | After kfunc call    | Trust preserved? |
|----------|---------------------|------------------|
| R0       | Return value        | New type from kfunc |
| R1-R5    | `NOT_INIT`          | No (cleared)     |
| R6-R9    | **Unchanged**       | **Yes**          |
| R10      | Frame pointer       | Always valid     |
| Stack    | Depends on helper   | Spilled ptrs may be clobbered if helper writes to stack |

### Exception: KF_RELEASE kfuncs

When a `KF_RELEASE` kfunc is called, ALL registers AND stack slots with
matching `ref_obj_id` are invalidated, regardless of caller-saved/callee-saved
status. But struct_ops callback arguments have `ref_obj_id = 0`, so they are
not affected by release sweeps.

---

## 9. Key Kernel Source References

All paths relative to `kernel/` in Linux v6.16:

- `bpf/verifier.c:14019` -- `clear_caller_saved_regs` after kfunc call
- `bpf/verifier.c:10322` -- `release_reference()` for KF_RELEASE
- `bpf/verifier.c:6304` -- `is_trusted_reg()` definition
- `bpf/btf.c:6428` -- `prog_args_trusted()` returns true for struct_ops
- `bpf/btf.c:6811` -- struct_ops args get `PTR_TO_BTF_ID | PTR_TRUSTED`
- `sched/ext.c:7212` -- `scx_bpf_task_running` flags: `KF_RCU`
- `sched/ext.c:7213` -- `scx_bpf_task_cpu` flags: `KF_RCU`
- `sched/ext.c:5850` -- `scx_bpf_dsq_insert` flags: `KF_RCU`
- `include/linux/btf.h:72` -- `KF_RCU` definition
- `include/linux/bpf.h` -- `PTR_TRUSTED` flag definition
