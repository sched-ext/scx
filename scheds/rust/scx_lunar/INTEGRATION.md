# scx_lunar — in-tree integration

Drop this directory into your scx fork as `scheds/rust/scx_lunar/`, then:

1. Register the crate in the workspace: add `"scheds/rust/scx_lunar"` to the
   `members` list in the repo-root `Cargo.toml`.

2. Build & run from the repo root:

   ```
   cargo build --release -p scx_lunar
   sudo ./target/release/scx_lunar --mode dsq_per_llc    # or dsq_per_cpu
   ```

## What changed vs. the standalone version

- **build.rs** uses `scx_cargo::BpfBuilder` — all include paths (scx/common.bpf.h,
  vmlinux.h, compat headers) come from the repo; no symlinks, no -I flags,
  no EXTRA_BPF_CFLAGS.
- **BPF source** renamed to `src/bpf/main.bpf.c` (in-tree convention).
  Include is now `<scx/common.bpf.h>`; `<include/bpf_experimental.h>` was
  dropped (nothing in the code used it; bpf_for etc. come from common.bpf.h).
- **UEI wired in** (required by `scx_ops_load!`): `UEI_DEFINE(uei)` +
  `lunar_exit` with `UEI_RECORD` + `.exit` in SCX_OPS_DEFINE. When the kernel
  ejects the scheduler (e.g. watchdog on a starved task), `uei_report!` now
  prints the reason instead of the scheduler silently vanishing.
- **Topology** comes from `scx_utils::Topology` instead of the hand-rolled
  sysfs walker: NUMA/hybrid/hotplug-aware. Kernel L3 ids are compressed to
  dense 0..nr_llcs indices (the DSQ id layout requires dense, <= 64).
  MAX_CPUS is checked against `NR_CPU_IDS` (possible CPU ids, holes included)
  rather than "highest cpuN + 1".
- **Skeleton lifecycle** uses the in-tree macros: `scx_ops_open!` (also
  handles hotplug_seq and the SCX_TIMEOUT_MS env override),
  `scx_ops_load!`, `scx_ops_attach!` (refuses to attach if another sched_ext
  scheduler is already running).
- **Restart loop**: a hotplug-triggered exit re-inits with fresh topology
  (`should_restart()`), matching the other in-tree schedulers.
- **CLI** switched to clap (`--mode`, `--exit-dump-len`, `--verbose`,
  `--version`, plus the standard libbpf option group). Mode values are still
  `dsq_per_llc` / `dsq_per_cpu`.

## Notes

- `.timeout_ms` is intentionally NOT set in SCX_OPS_DEFINE, keeping the
  kernel-default 30s watchdog as the starvation budget for the GREEDY queue.
  Override at runtime with `SCX_TIMEOUT_MS=<ms>` (handled by scx_ops_open!) —
  only values <= 30000 are accepted by the kernel.
- Path deps (`scx_utils`, `scx_cargo`) intentionally omit version pins so the
  crate tracks whatever your fork checkout has. If cargo complains about
  workspace version fields, mirror what a neighboring scheduler's Cargo.toml
  does in your checkout.
- Keep changes outside this directory to the one-line workspace registration
  so `git merge upstream/main` stays conflict-free.
