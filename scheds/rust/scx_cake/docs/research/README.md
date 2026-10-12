# Research and experimental patches

Current verdicts live in the [STATE.md](../../STATE.md) pattern ledger, with each
pattern's kernel requirement. This page indexes the investigations.

| Investigation | Status (2026-10-04) | Start here |
|---|---|---|
| Custom kernel patch: scalar kfuncs, fastcall, bounds, DSQ index, wake signals | Installed on the host (7.2.9); native CTZ/POPCNT on by default, fastcall and bounds no effect, DSQ index and signals untested on hardware | [JIT prototype](jit-bitops-prototype/README.md), [full patch](jit-bitops-prototype/0001-cake-kernel-full-signals-experimental-cachyos-7.2.8.patch) |
| All-in-one patch with the lean idle claim (K1-K4) | Written 2026-10-05 for CachyOS 7.2.9-1: applies cleanly, touched objects compile; not installed | [patch](jit-bitops-prototype/0001-cake-kernel-full-signals-idle-experimental-cachyos-7.2.9.patch) (sections indexed in its header) |
| Cake/kernel caching | Source review; DSQ direct index built into the patch | [Cache review](jit-bitops-prototype/CACHE_HOTPATH_REVIEW_2026-10-02.md) |
| Unary fastcall | No measurable effect on hardware | [Fastcall review](jit-bitops-prototype/FASTCALL_KERNEL_REVIEW_2026-10-01.md) |
| BPF/compiler/JIT boundary | Compiler probes and JIT inspection | [Investigation](jit-20260929/README.md) |
| Exact reciprocal quotient | Removed 2026-10-04 (BPF +5.8 %); sources kept | [Implementation](jit-bitops-prototype/QUOTIENT_IMPLEMENTATION.md), [sources](jit-bitops-prototype/quotient/) |
| Counting, classifiers, inclusion–exclusion | Measured 2026-10-05: spread pick rejected; wide-host idle count, interlock and exit/census checks kept (uncommitted); K3 premise holds | [Report](counting-classifiers-20261005/README.md) |
| Block stash: wake classes from one line (cache-line follow-up) | Rejected 2026-10-12: no frame effect in KovaaK's; reverted | [Report](block-stash-20261012/README.md) |
| claimhome: lean `lazy`'s placement without the kernel patch | Not shipped 2026-10-12: placement reproduced, frame win needs the cheaper claim too | [Report](claimhome-20261012/README.md) |

The [meeting page](../meeting/index.html) summarizes the work; the
[cost audit](../AUDIT_OPERATION_COST_2026-09-15.md) explains evidence levels.
The retained 0002 Cake patch is historical; do not apply it to this checkout.

Each investigation keeps its objects, patches, harness and manifests together;
do not move them without updating provenance. Build outputs live in the
repository's `target/`; run outputs in `scx_cake_bench/runs/`.

New investigations get their own directory and README stating the evidence
level (source review, model, verifier, VM, hardware, game) and the kernel
requirement. A passed build or VM test is not a speedup.
