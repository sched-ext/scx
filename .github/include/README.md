# GitHub Actions CI Scripts

## list-integration-tests.py

Generates the test matrix for integration tests with intelligent filtering based on changed files.

### How It Works

1. **Detects Changed Files**: Uses `git diff` to find files changed between the PR branch and the base branch.

2. **Categorizes Changes**:
   - **Core changes**: Files in `rust/scx_utils/`, `rust/scx_stats/`, `.github/`, `.nix/`, etc.
   - **Library changes**: Files in `rust/scx_rustland_core/` or other local dependencies
   - **Scheduler changes**: Files in `scheds/rust/scx_*/`

3. **Builds Dependency Graph**: Parses `Cargo.toml` files to understand which schedulers depend on which libraries.

4. **Generates Filtered Matrix**:
   - Core changes → Test all schedulers
   - Library changes → Test schedulers that depend on that library
   - Scheduler changes → Test only that scheduler
   - Mixed changes → Test union of affected schedulers

### Forcing Full Test Runs

If you need to test all schedulers regardless of changes, you can:

1. **Commit trailer method**: Add to your commit message:
   ```
   CI-Test-Kernel: sched_ext/for-next
   ```

2. **Modify core files**: Touch a file like `.github/workflows/caching-build.yml` to trigger full tests

### Testing Locally

Run the test script:
```bash
.github/include/test-selective-matrix.sh
```

Or manually:
```bash
# Simulate PR context
export GITHUB_BASE_REF=main
python3 .github/include/list-integration-tests.py sched_ext/for-next
```

### Matrix Output Format

The script outputs a JSON array of objects:
```json
[
  {"name": "scx_bpfland", "flags": "", "kernel": ""},
  {"name": "scx_layered", "flags": "--disable-topology=false", "kernel": ""}
]
```

This is consumed by the GitHub Actions workflow to create the test matrix.
