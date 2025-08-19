#!/usr/bin/env bash
# Experiment 5: 1 cgroup, 2 threads, 2 CPUs — verify threads stay on CPUs 7 and 8 (different L3s), log total busy (%) for those CPUs.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CGROUP_CLI="$SCRIPT_DIR/../cgroup_cli.sh"

UNIT_NAME="${UNIT_NAME:-expt5}"
TARGET_CPU1="${TARGET_CPU1:-7}"   # override via env if desired, e.g. TARGET_CPU1=7 ./exp5_1cgrp_2th_2cpu.sh
TARGET_CPU2="${TARGET_CPU2:-8}"   # override via env if desired, e.g. TARGET_CPU2=8 ./exp5_1cgrp_2th_2cpu.sh

command -v mpstat >/dev/null || { echo "mpstat not found (install 'sysstat')"; exit 1; }

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  "$CGROUP_CLI" stop "$UNIT_NAME" || true
}

trap cleanup EXIT

printf "=== Experiment 5: 1 cgroup, 2 threads, 2 CPUs — threads on CPUs %s and %s (different L3s) ===\n" "$TARGET_CPU1" "$TARGET_CPU2"
printf "Starting workload:\n"

# Start workload with 2 threads on CPUs 7 and 8
"$CGROUP_CLI" start "$UNIT_NAME" "$TARGET_CPU1,$TARGET_CPU2" 2

printf "Monitoring. Expect CPUs %s and %s ≈ 100%% busy; others mostly idle. Press Ctrl+C to stop.\n\n" "$TARGET_CPU1" "$TARGET_CPU2"
printf "Alternatively, we may see both tasks allocated to the same CPU. Poor work conservation, motivates work stealing."

# Monitor
"$CGROUP_CLI" monitor
