# Cake BPF/JIT investigation — 2026-09-29

## Finding

The meeting's premise is correct: the kernel's architecture JIT selects the
final native instructions. However, it receives BPF bytecode, not the original
C builtin or LLVM bit-count intrinsic. Clang's BPF backend expands the bit-count
request before that boundary. The inspected reference x86 JIT does not recognize
the resulting CTZ/popcount/CLZ sequences and collapse them back to bit-count
instructions. Adding a kfunc is one solution, not the only possible solution.

Fresh compiler probes demonstrate the expansion on the installed Clang. Saved
September 27 loaded Cake BPF demonstrates the corresponding real Cake paths.
Current Cake native JIT code has not been captured; no claim of an exact current
native instruction count or live speedup follows from this investigation.

## Evidence collected

| Evidence | Result | Limit |
|---|---|---|
| Cake source | `8fc5ec9b1`; existing documentation changes preserved | No scheduler code changed |
| Running kernel | `7.2.8-1-cachyos`, JIT enabled, sched_ext disabled | No scheduler activated |
| Installed kernel ELF | GNU build ID `424ea18dbf0262d3f9c8a2205b292c577c338802` matches `/sys/kernel/notes`; `.BTF` byte-for-byte matches `/sys/kernel/btf/vmlinux` | Matches installed binary to live identity; does not authenticate a source checkout or prove emitted Cake code |
| Local source reference | Linux `2709dd5ae32f0828f386327c76bba9f39f63a1c6` | Not proven to be the running kernel's source; unrelated untracked `mutex_handoff.c` left untouched |
| Native kernel JIT implementation | `do_jit` and `bpf_int_jit_compile` disassembled from matching installed ELF | This is the compiler's own machine code, **not** machine code it generated for Cake |
| BPF program inspection | `bpftool -j prog show` returned `Operation not permitted`; bpftool has no file capabilities | No privileged workaround or security-setting change attempted |
| Address visibility | `kernel.kptr_restrict=2`; reading `bpf_jit_harden` denied | Hardening value unknown; do not assume it is disabled |
| Retained JIT dumps | All 16 September 27 files contain retrieval errors | Filenames do not constitute native-disassembly proof |

Full hashes and identity: [provenance.json](provenance.json).
Compiler version: [toolchain.txt](toolchain.txt).
Installed compiler implementation: [installed-jit.asm](installed-jit.asm).

## Reproduced compiler boundary

Compiled the same [six small C probes](bitops.c) with Clang 22.1.8 for both BPF
and native Zen 5. Neither object was loaded or executed in the kernel.

```sh
clang -O2 -g -target bpf -mcpu=v4 -c bitops.c -o bitops.bpf.o
llvm-objdump -dr --no-show-raw-insn bitops.bpf.o > bitops.bpf.asm
clang -O2 -march=znver5 -c bitops.c -o bitops.x86.o
llvm-objdump -dr --no-show-raw-insn bitops.x86.o > bitops.x86.asm
```

| Probe | BPF operations, excluding exit | Native Zen 5 core code, excluding return/alignment |
|---|---:|---|
| CTZ, nonzero input | 9 | `tzcntq %rdi, %rax` |
| CTZ, zero returns 64 | 11 | `tzcntq %rdi, %rax` |
| Population count | 19 | `popcntq %rdi, %rax` |
| CLZ, zero returns 64 | 40 | `lzcntq %rdi, %rax` |
| Isolate lowest set bit (`x & -x`) | 3 | `blsiq %rdi, %rax` |
| Rotate left | 8 | Two argument/result moves plus `rolq %cl, %rax` |

These are **BPF operations versus native compiler output**, not measured BPF-JIT
output. Wide BPF immediates consume two encoding slots but count as one operation
here. A BPF conditional branch can become compare + branch, so the defined CTZ
probe's 11 BPF operations are consistent with the older 12-x86-instruction
standalone translation. Counts exclude surrounding Cake ranking/claim code.

Disassemblies: [BPF](bitops.bpf.asm), [native x86](bitops.x86.asm).
Machine-readable operation lists: [counts.json](counts.json).

LLVM's [BPF target lowering implementation](https://llvm.org/doxygen/BPFISelLowering_8cpp_source.html)
explicitly marks CTPOP, CTTZ and CTLZ for expansion. That published source is
corroborating design evidence; the locally generated objects are evidence for
the installed compiler's behavior.

## What the reference JIT actually does

Source: `/home/ritz/Documents/Repo/linux/arch/x86/net/bpf_jit_comp.c` at the
reference commit above; line numbers are for that checkout.

- `do_jit`, around 1867: walks BPF instructions and switches on their opcode.
- Around 1885: ADD/SUB/AND/OR/XOR emit their corresponding x86 ALU operation.
- Around 1957: NEG emits native negation.
- Around 2019: wide immediate load emits the immediate; consumes its second
  BPF encoding slot. This lookahead is not bit-scan recognition.
- Around 2025: DIV/MOD emit DIV/IDIV with the necessary register save/setup.
- Around 2094–2118: multiplication emits IMUL.
- Around 2142: variable shifts use BMI2 when suitable; an existing example of
  CPU-feature-aware selection.
- Around 2561: fetch-AND/OR/XOR use a CMPXCHG retry loop; non-fetch atomics can
  use direct locked operations.
- `bpf_int_jit_compile`: multiple passes resolve code sizes/branches, allocate
  code and finalize it. Repeated passes do not imply LLVM-style optimization.

Searches across `arch/x86/net`, `kernel/bpf`, and the BPF UAPI found no CTZ/CLZ/
POPCNT recognition, de Bruijn pattern, or relevant bit-count opcode in this
reference. Inspection of the opcode cases shows individual emission, rather
than a scan across the software bit-count sequence. Thus the reference JIT
retains the sequence; this is stronger than reasoning from a builtin name.

Some optimization happens before the architecture JIT. `kernel/bpf/fixups.c`
rewrites jiffies and CPU-ID helpers around lines 2145 and 2171. The historical
Cake xlated dump confirms CPU ID became a per-CPU access. General statements
that every helper call pays call/return overhead are incorrect.

Do not search the JIT implementation's disassembly for the mnemonic `tzcnt`
and treat its presence/absence as generated-code proof: the compiler can itself
use bit instructions, while an emitter constructs instruction bytes as data.

## Why recognizing the existing sequence is not a trivial substitution

Cake's CTZ path isolates a bit, hashes it, then reads a table through a BPF map
address. A correct JIT pattern optimization must establish more than a familiar
multiply constant:

1. The table contents and lifetime/immutability must make the lookup equivalent
   to CTZ. Arbitrary BPF code can use that constant with a different table.
2. No branch may enter the middle of the rewritten region.
3. Any intermediate registers used later must retain their required values;
   replacing the final answer alone can change observable program behavior.
4. Zero-input behavior and 32/64-bit widths must match the original bytecode,
   not merely the C programmer's likely intention.
5. Hardware feature checks and fallback behavior must be correct. The TZCNT
   encoding has different semantics on CPUs lacking BMI1.
6. Constant blinding, verifier rewrites and changes in LLVM lowering can alter
   the pattern. This affects recognition and test coverage.

These are engineering requirements, not proof that a peephole optimization is
impossible. Pure arithmetic popcount has no table-content dependency and could
be a more contained pattern candidate, but still needs control-flow/register
correctness. `x & -x` → BLSI is a smaller arithmetic candidate demonstrated by
the probes, though no separate Cake performance benefit is established.

## Implementation routes

| Route | Main advantage | Work / risk |
|---|---|---|
| JIT pattern recognition | Existing BPF binaries may benefit without a new API | Must prove bytecode equivalence, handle intermediate state/control flow/table semantics and compiler variations |
| Explicit BPF bit-count instruction | Preserves operation intent across compiler and kernel; natural register operands | Compiler support, verifier semantics, interpreter and architecture-JIT support, feature negotiation and ISA coordination |
| JIT-inlined bitops kfunc | Explicit intent using a function-shaped API; existing proposal | Registration and program-type eligibility, return ranges, CPU fallback, inlining and call-ABI/spill handling |

The [February bitops series](https://www.mail-archive.com/linux-kernel%40vger.kernel.org/msg2612625.html)
and [x86 implementation proposal](https://lists.openwall.net/netdev/2026/02/19/110)
are relevant starting points, not a confirmed merged feature. Review discussions
also considered a `KF_JIT_MAY_INLINE` design; no claim of current acceptance or
latest-series status is made here.

Recommendation: take the explicit-operation question to BPF/JIT maintainers
with these reproductions. CTZ and POPCNT are the immediate Cake users. Do not
assume kfunc inlining is the chosen design, nor that kernel-only recognition
must be preferable. Require native-code inspection to compare register overhead.

## Next validation gate

The remaining definitive test needs an authorized BPF inspection/loading path:
load an unattached minimal probe, retain verifier-translated BPF and actual JIT
bytes, and compare both the existing kernel and candidate implementation. This
need not replace the active scheduler. A later Cake test must bind its exact
binary/object to the kernel and use the maintained paired measurement route.

For a proposed patch, first verify zero/all-one/single-bit/random inputs,
feature-disabled fallback and 32/64-bit forms; for pattern matching, include
adversarial tables, branch entries and live intermediate registers. Then measure
dependent and independent operations, full callback cost and scheduling outcomes.

No system settings, capabilities, packages, kernel source, or scheduler behavior
were changed. Native program inspection remains permission-blocked; the static
investigation and reproducible compiler comparison are complete.
