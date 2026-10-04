# Research and experimental patches

| Investigation | Status | Start here |
|---|---|---|
| Cake/kernel caching, October 2 | Source review; direct DSQ index and lookup reuse proposed, no new implementation or timing result | [Existing caches, validity and next experiment](jit-bitops-prototype/CACHE_HOTPATH_REVIEW_2026-10-02.md) |
| Unary fastcall and further kernel paths, October 1 | Full kernel and annotated release built; native/fallback/old-kernel VM checks pass; mixed static JIT changes, hardware performance unmeasured | [Patch, evidence and next mechanisms](jit-bitops-prototype/FASTCALL_KERNEL_REVIEW_2026-10-01.md) |
| BPF/compiler/JIT boundary, September 29 | Compiler probes and installed JIT implementation inspected; host Cake native dump unavailable | [Investigation](jit-20260929/README.md) |
| Explicit CTZ/POPCNT kfuncs and x86 inlining | Patched-hardware primitive correctness and actual JIT emission passed September 30; noisy timings diagnostic only; Cake native-mode loading and performance acceptance pending | [Patch bundle and testing](jit-bitops-prototype/README.md), [hardware smoke](jit-bitops-prototype/HARDWARE_SMOKE_2026-09-30.md) |
| Complete exact reciprocal quotient, September 30 | Normal-build opt-in implemented; differential arithmetic and build checks passed; native CLZ/MULHI kernel extension prepared; live verifier/activation and performance pending | [Implementation and manual test](jit-bitops-prototype/QUOTIENT_IMPLEMENTATION.md), [registered experiment](jit-bitops-prototype/QUOTIENT_EXPERIMENT.md) |

Read the investigation for the problem and the prototype for the implementation.
The [meeting page](../meeting/index.html) summarizes both; the
[cost audit](../AUDIT_OPERATION_COST_2026-09-15.md) explains the evidence levels.
The normal Cake source now auto-detects native bitops at startup, with portable
fallback; `--portable-bitops` forces that fallback for comparison. Explicit
native flags remain strict and `--division-free` remains off by default. See
[current defaults and validation](jit-bitops-prototype/AUTO_NATIVE_BITOPS_2026-10-02.md).
The retained 0002 Cake patch is historical and should not be applied again to
this checkout.

The investigation keeps small compiler objects, disassembly and hash manifests
together. Do not move or regenerate those artifacts without updating provenance.
The prototype keeps patch files, the measurement harness, VM configuration,
registered experiment and validation manifest together. Its build outputs live
in the repository's `target/cake_jit_bitops_20260929/`; actual run outputs live in
the sibling `scx_cake_bench/runs/jit_bitops_20260929/`.

New investigations should use their own directory and README. Mark whether
evidence is source review, offline modeling, verifier acceptance, VM execution,
hardware measurement or full scheduler/game measurement. A passed build or VM
test does not imply a scheduler speedup.
