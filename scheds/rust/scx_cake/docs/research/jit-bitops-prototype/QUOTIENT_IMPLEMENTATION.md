# Exact quotient implementation — 2026-09-30

**October 1 update:** the combined patch is booted and Cake passed a 15-second
live smoke with both flags and `CLZ/MULHI kernel`. Verifier loading and clean
native restoration passed on this host. See [current evidence](HARDWARE_SMOKE_2026-10-01.md).
The implementation-time kernel status and remaining gates below are historical;
fresh primitive selftests, actual JIT dumps and performance testing remain owed.

The normal Cake source implements the complete unsigned quotient, selected by
`--division-free`. This replaces four dynamic division expressions: mean burst,
service quotient, starvation burst, and diagnostic release burst. Constant
divisions remain unchanged. There is no new task state or scheduling policy.
Both `--division-free` and `--native-bitops` default off and are independent.

## Build and test

The local command is installed as `~/.local/bin/cake`, pointing to the tracked
`scheds/rust/scx_cake/cake` helper. It uses the repository's normal release target
and keeps temporary build files under `target/cake_build_tmp`.

```sh
cake build
cd /home/ritz/Documents/Repo/scx/target/release
sudo ./scx_cake --division-free --native-bitops
```

For quotient alone use `sudo ./scx_cake --division-free`. Omit both flags for
the default division/bitops implementation. Ctrl+C stops the foreground Cake
instance. Startup explicitly reports `Division-free true (CLZ/MULHI portable)`
or `Division-free true (CLZ/MULHI kernel)`, as well as native bitops selection.

The user explicitly requested this manual sudo launch and will perform the live
test. It is a functionality smoke test; it is not a receipt-backed benchmark
or performance acceptance. The OS was reported noisy.

## Native kernel extension

At implementation time, the installed 7.2.8 custom kernel exposed CTZ/POPCNT
only, so quotient testing used portable CLZ and 32-bit-limb MULHI. The additional
kernel build is now booted; the October 1 smoke confirms native path selection.

For the same CachyOS **7.2.8-1** source, select this **single combined patch**:

[0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch](0001-bpf-x86-inline-all-scalar-ops-cachyos-7.2.8.patch)

It includes all four operations: CTZ/TZCNT, POPCNT, CLZ/LZCNT, and unsigned
MULHI. Replace the older 0001 entry and any 0003 entry in Kernel Manager's
patch list with this file. Restart the normal build so it extracts clean
sources; do not apply the combined patch on top of the older patches.

Keep the existing custom kernel as a boot option. Do not supply the historical
0002 scx source patch to Kernel Manager. The combined patch is specific to the
validated 7.2.8 source. The older 0001/0003 files remain historical references.

The combined patch includes `bpf_clz64(x)` (zero returns 64) and `bpf_mulhi64(x,y)` (unsigned high
64 bits). The x86 JIT emits LZCNT when ABM/LZCNT is supported and otherwise
retains the kernel call. MULHI emits `mov RAX,RDI; mul RSI; mov RAX,RDX`, using
only caller-scratch registers. Normal BPF call argument/spill rules still apply.
Portable kernel implementations and the extended boundary/random/R6–R9
preservation selftests are included.

Cake automatically selects these two kfuncs with `--division-free` when both
symbols and x86 LZCNT support are present. It reports this selection; the
existing `--native-bitops` option independently selects CTZ/POPCNT.

## Arithmetic

`src/bpf/quotient.bpf.h` implements Algorithm 2 from Möller and Granlund,
[*Improved division by invariant integers*](https://gmplib.org/~tege/division-paper.pdf).
The 256-entry integer seed table and refinements produce the exact reciprocal
`v = floor((2^128-1)/D) - 2^64` for normalized `D >= 2^63`.

For divisor `d`, normalization uses `s = clz(d)` and `D = d << s`. The high
product and carry yield `q0 = floor(a*(2^64+v)/2^(128-s))`. Since the reciprocal
rounds down, `q0 <= floor(a/d)`. Its real-valued error is less than
`a*2^s/2^128 < 1`, so it underestimates by at most one. Compute `r = a-q0*d` and
add one when `r >= d`. Multiplication cannot overflow the true remainder
calculation because `q0*d <= a`. Intermediate unsigned wraps in the reciprocal
algorithm are intentional.

Zero divisors return zero, matching BPF DIV behavior. Divisor 1, numerator below
divisor, powers of two, and divisors at least `2^63` have explicit exact paths.
All shifts and table indexes are bounded. No dynamic division or floating point
is used in the candidate. MULHI uses four bounded limb products when native
support is absent; an optimizer barrier prevents LLVM from generating an
unsupported BPF 128-bit multiplication.

## Validation and remaining gates

Retained implementation evidence: `target/cake_quotient_20260930/`.

- Portable and host-native MULHI quotient variants, both with UBSan:
  **7,907,120 quotient comparisons each**, zero mismatches. Includes zero,
  small exhaustive inputs, powers of two and neighbors, exact multiples and
  their neighbors, u64 extremes, and randomized wide/narrow denominators.
- Each variant also checks **2,001,536 normalized reciprocals** against u128
  division and **2,000,000 portable MULHI products** against u128 products.
- Cake: 33 unit tests and 3 integration tests passed; the existing privileged
  verifier test is ignored. Package Clippy and formatting passed. Normal
  `cake build` release build passed and exposes both flags.
- 0003 passes zero-fuzz dry-run application. Updated x86 JIT and helper objects
  compile with the retained 7.2.8 config/toolchain/include environment; the
  extended BPF selftest object also compiles. These are object checks, not a
  full kernel build or boot test.
- The single combined patch also passes clean-source git application and
  zero-fuzz GNU patch application. All five resulting files are byte-identical
  to 0001 plus 0003; recompiled JIT/helper/BPF selftest objects pass. Checkpatch
  has zero errors, one new-file MAINTAINERS reminder and one inherited asm
  formatting check. Logs and hashes:
  `target/cake_quotient_20260930/kernel/combined/validation.json`.

Live full-Cake verifier acceptance/activation, native-kernel CLZ/MULHI selftest
execution and actual JIT dumps remain pending. No complete quotient speedup is
claimed. The earlier cakesim LZCNT benchmark measured normalization only and
discarded the numerator; this implementation computes and checks the quotient.
Reciprocal setup and normal BPF call overhead are included in the mechanism and
must be measured before accepting a performance gain.
