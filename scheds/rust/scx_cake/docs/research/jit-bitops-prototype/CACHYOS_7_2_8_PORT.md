# CachyOS 7.2.8-1 patch port

**September 30 update:** for all four operations, use the
[single combined patch](0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch).
Replace the older local patch entries with this one file and build from freshly
extracted sources. The original CTZ/POPCNT-only port described below is retained
as historical evidence. See [current build/test instructions](QUOTIENT_IMPLEMENTATION.md).

The Kernel Manager screenshot selected `cachyos-7.2.8-1.tar.gz`, not 7.3-rc4.
The original development-tree patch failed its second x86 JIT hunk because
7.2.8 lacks the newer `emit_kfunc_arena_args` block. This was a source-context
mismatch during prepare(), before the kernel compile.

Use [0001-bpf-x86-inline-scalar-bitops-cachyos-7.2.8.patch](0001-bpf-x86-inline-scalar-bitops-cachyos-7.2.8.patch)
instead of the original 0001 for this source. Select only one kernel patch.
Remove the old entry, add this file, and restart the normal Kernel Manager build
so its prepare stage operates on freshly extracted sources. Do not resume a
manual compile of the partially patched tree or ignore its reject file.

The port keeps the same kfunc semantics, CPU gates and emitted instructions.
Its call-site check is after the zero-immediate rejection and before private
frame-pointer saving/call-depth accounting. It is gated on BPF_PSEUDO_KFUNC_CALL;
these scalar instructions change RAX using RDI and do not clobber R9. The ordinary
call path remains the fallback. Header context was regenerated for this version
as well, removing the fuzzy match shown in the failed attempt.

Validated against pristine affected files extracted from the exact downloaded
CachyOS archive:

- All five paths pass git apply --check.
- GNU patch --dry-run --fuzz=0 passes without offsets or fuzzy matches.
- The x86 JIT and BPF helper objects compile with LLVM using the installed
  7.2.8 configuration, including ThinLTO.
- Checkpatch reports zero errors and one new-file MAINTAINERS reminder.

These are application and affected-object build checks. Full package linking,
NVIDIA module building, booting, live JIT correctness and hardware performance
remain for the selected build. The original VM results do not constitute a
runtime test of this port. No Kernel Manager cache files were modified by the
repair; isolated sources and logs are retained under
`scx/target/cake_jit_bitops_20260929/cachyos-7.2.8-port/`.

[Validation and hashes](validation-cachyos-7.2.8.json).
