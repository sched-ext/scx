# One kernel patch for the current Cake research stack

Use [0001-cake-kernel-full-experimental-cachyos-7.2.8.patch](0001-cake-kernel-full-experimental-cachyos-7.2.8.patch)
as the **single replacement patch for fresh CachyOS 7.2.8-1 sources**. It includes
the original scalar operations, unary fastcall, verifier return bounds, typed DSQ
comparison and the direct DSQ index. It is a research bundle with outstanding
debug and hardware-performance gates, not a newly validated production release.

## Which changes require a new kernel?

| Change | Kernel requirement | Cake requirement |
|---|---|---|
| Current native CTZ/POPCNT and wrapper cleanup | Already supported by the booted scalar-patched kernel | Already in the repo release, including automatic fallback |
| Unary fastcall and precise return bounds | Build and boot this newer kernel | The full measured instruction reduction also requires the separate annotated/specialized Cake build |
| Typed DSQ comparison | Build and boot this newer kernel | Existing Cake calls benefit from the changed implementation automatically |
| Direct DSQ index | Build and boot this newer kernel | Existing Cake queue IDs use it automatically; no new flag or API needed |

The current ordinary Cake release retains masks and runtime mode selection.
Installing the kernel does not turn it into the specialized research executable
that removed 26 static select_cpu instructions and 13 BPF stack accesses.
That executable is retained in the [bounds/specialization experiment](SCALAR_BOUNDS_REFACTOR_2026-10-02.md).
Portable integration of that specialization needs a compatible-object fallback
and a probe of the actual verifier contract; symbol presence alone is insufficient.

## Contents

1. `bpf_ctz64`, `bpf_popcnt64`, `bpf_clz64`, `bpf_mulhi64` and their x86 JIT
   emitters: TZCNT, POPCNT, LZCNT and the upper half of unsigned MUL.
2. Unary KF_FASTCALL support with register-preserving C fallbacks. MULHI keeps
   its ordinary ABI because its implementation clobbers a register that unary
   fastcall promises to preserve.
3. Trusted CTZ/CLZ/POPCNT return ranges and input precision tracking for
   nonzero-dependent bounds.
4. Existing scalar boundary, randomized and register-preservation selftests.
5. Typed u64 DSQ comparison, backported from work authored by Usama Arif.
6. Optional 2048-entry RCU DSQ index, serialized lifecycle updates, hash fallback,
   teardown cleanup and allocation/status controls.

The CLZ/MULHI capabilities remain available without enabling Cake's division-free
algorithm. Division-free, queue scanning and diagnostic histograms remain off in
the ordinary Cake release. This file changes kernel source only; it does not
patch Cake source, alter its flags or install either component.

## Applying with the existing kernel build workflow

In the Kernel Manager patch list for **7.2.8-1**, replace earlier custom Cake
scalar/fastcall/bounds/typed-DSQ/direct-index entries with this one file. Keep
unrelated kernel patches and the normal hardware configuration. Start from
freshly extracted matching sources; do not apply the bundle over a source tree
that already contains the older Cake patches.

Build/install through the existing kernel packaging workflow, keeping the
current kernel available as a boot option, then boot the new kernel and start
the repo Cake release. No running kernel changes until that boot. Other kernel
versions require a fresh application/build check; this bundle is version-specific.
The minimal VM configuration from research is not a desktop kernel configuration.

The new kernel enables the direct index by default if allocation succeeds.
`sched_ext.dsq_direct=0` on its boot command line forces the original hash path
for a controlled comparison. With Cake attached, the candidate's
`/sys/kernel/sched_ext/root/dsq_direct_entries` reports 2048 or 0. Queue heads
and counts are still read live in both modes.

## Validation of this combined file

The source archive was the retained
`/home/ritz/.cache/cachyos-km/pkgbuilds/linux-cachyos/cachyos-7.2.8-1.tar.gz`.
All existing affected files were freshly extracted; the two new selftest files
were confirmed absent. The archive, component patches and before/after source
hashes are recorded in the [validation manifest](KERNEL_FULL_BUNDLE_VALIDATION_2026-10-02.json).

- `git apply --check` passed.
- GNU patch applied all eight files with zero fuzz and zero offsets.
- Reverse `git apply --check` passed.
- **All eight resulting files match the retained built/tested DSQ candidate
  byte for byte**, including the JIT, helpers, verifier and selftests.
- Checkpatch with `--strict --no-signoff` reports zero errors, two warnings
  and two checks. The inherited selftest notices concern new-file MAINTAINERS
  coverage, intentional mutable `volatile` input, and multiline BPF assembly
  formatting. They are retained to preserve exact tested source. No submission
  sign-off is asserted.

This packaging step ran no new kernel compilation or VM benchmark. It reproduces
the affected source of the prior candidate whose ordinary image SHA-256 is
`2c785c1a6fc0c30197ff6410a3ff414c9a941011a588eab7837439621d73aacf`.
That candidate passed six ordinary-kernel VM configurations and 20 simulation
slots; [the report](DSQ_DIRECT_INDEX_2026-10-02.md) records the limits and raw data.

The POC lock-order warning and early-boot KASAN report also reproduced on the
baseline. This bundle does not repair them. A subsequent source review found a
close upstream match for the KASAN failure involving transient LA57 capability
state during CPU identification; `no5lvl` is a proposed diagnostic here, not a
locally verified fix. See the [upstream report](https://lists.openwall.net/linux-kernel/2026/06/10/2083).
Clean debug validation and hardware performance remain open.

The host kernel, system package and repo Cake executable were unchanged by
bundle preparation. Applying/building this file is a separate action from
installing and booting a kernel.
