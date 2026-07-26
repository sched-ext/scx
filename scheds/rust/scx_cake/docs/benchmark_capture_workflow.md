# Benchmark capture workflow

The former in-tree capture, suite, policy, matrix, and profiling workflow is
retired. It required root execution, repaired ownership after runs, and could
not prove that the activated binary and BPF object came from the reviewed
source.

Current development and benchmarking are owning-user only:

1. Enter through `/home/ritz/Documents/Repo/scx/cakebench`, which delegates to
   `/home/ritz/Documents/Repo/scx_cake_bench_assets/cakebench`.
2. Treat missing capabilities, perf access, tracing access, or artifact
   receipts as hard preflight failures. Do not change privileges during a run.
3. Use the canonical one-shot identity broker for a narrow code-variant screen.
   Generated mutation plans are evidence, not launch recipes.
4. Require a strict v5 binary/BPF receipt, current-boot validation, activation
   proof, exact active scheduler identity, and disabled-state restoration.
5. Use randomized or ABBA complete blocks, A/A drift evidence, multiplicity
   control, and a clean native-versus-candidate holdout before promotion.

The retired scripts remain as non-executable fail-closed stubs so old links do
not silently revive the obsolete workflow. Historical reports and captures are
evidence only and do not authorize replaying their commands.
