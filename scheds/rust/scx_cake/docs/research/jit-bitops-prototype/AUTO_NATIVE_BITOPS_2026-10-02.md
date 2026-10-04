# Automatic native bitops for game testing

The user requested native CTZ/POPCNT by default with automatic fallback on
machines without the kernel patch. The release loader now detects the running
CPU and kernel before loading BPF. It never selects the mode at compile time.

| Invocation | Selection |
|---|---|
| No bitops options | Use each native operation when its CPU feature and kernel BTF symbol exist; otherwise use its portable implementation |
| `--portable-bitops` | Force both operations portable for game comparisons |
| `--native-bitops` | Require both native operations; report an error if unsupported |
| `--native-ctz` / `--native-popcnt` | Require only the specified operation, preserving the independent research comparisons |

The portable override conflicts with explicit native bitops and queue-scan
options. Startup logs report effective CTZ and POPCNT selection. Division-free,
experimental queue scanning, diagnostic histograms and the probe stay off by
default. Later fastcall/bounds/DSQ kernel candidates are not installed by this
change. User-requested default selection is not a new game-performance verdict.

## Validation

- `cargo test --locked -p scx_cake`: 37 unit tests and 3 CLI tests passed;
  one separately gated topology load test remains ignored.
- Debug and release package Clippy passed with `--all-targets --no-deps -- -D warnings`.
  Cargo still reports the unrelated `scx_rustland_core` manifest's unused `lib.include` key.
- Optimized release build, formatting and diff checks passed.
- Three load-only host inspections passed: automatic native, forced portable,
  explicitly required native. Host scheduler remained disabled and BPF statistics off.
- Patched 7.2.8 VM: automatic native and forced portable both loaded, attached,
  served workers, exited cleanly and restored native Linux scheduling.
- Unpatched stock CachyOS 7.2.8 VM: automatic and forced portable both passed
  the same checks; explicitly required native failed with the expected message.
- A portable test kernel with the scalar patch and QEMU CPU features
  BMI1/POPCNT/ABM disabled: automatic fallback and forced portable both passed;
  explicitly required native failed as expected. This validates runtime CPU
  detection separately from absent kernel symbols.
- Total final VM checks: seven accepted inspection loads, two expected
  pre-load native-requirement rejections and six activation/restoration checks.
  No kernel BUG/Oops/WARNING in the three accepted VM logs.

Initial VM harness attempts could not boot because the retained BusyBox and
host-tuned kernel required CPU features unavailable in the guest. The corrected
harness uses a baseline-linked C init, the stock kernel for missing-symbol
testing, and a portable patched kernel for missing-CPU-feature testing.
Failed attempts are retained separately; they never ran Cake and are not counted
as validation. Minimal guests lack `sha256sum`, producing a startup identity
warning; the exact embedded executable is hash-recorded in the initramfs manifest.

Release SHA256: `059f78b352ef5c796754691ecd38dbbf0c896b10c2d0a85a383f1609fed94fef`.

Embedded BPF SHA256: `889948f8cf0dff94238379fc9b39664314d9c2cc511cbcee89cba79c129d9b2c`.
The complete BPF object occurs exactly once in the new executable and is
byte-for-byte identical to the measured wrapper-cleanup candidate. Only Rust
startup selection and CLI changed; no scheduling hot-path refactor was added.

Candidate, backups and reproducible checks:
`target/cake_auto_bitops_20261002T175818Z/`.

Measurement and validation logs:
`../scx_cake_bench/runs/cake_auto_bitops_20261002T175818Z/`.

The current release is `target/release/scx_cake`. A capability-provisioned
copy for ordinary user launch is
`target/cake_receipt_builds/cake_auto_bitops_20261002T175818Z/scx_cake`.
No additional flags are needed for the requested automatic mode.

The user will run the repo release and keep the CachyOS system package.
`/usr/bin/scx_cake` is unchanged; no host scheduler was started by this
preparation. `deployment.json` records the repo-only outcome. A copy of the
prior system executable is retained as `installed-before-scx_cake`.
