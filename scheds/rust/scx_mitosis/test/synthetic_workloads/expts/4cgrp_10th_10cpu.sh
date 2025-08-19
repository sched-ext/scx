#!/usr/bin/env bash
# Experiment 3: 4 cgroups, 10 threads each, 10 CPUs each — verify thread distribution across multiple cgroups
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CGROUP_CLI="$SCRIPT_DIR/../cgroup_cli.sh"

# 4 cgroups with their respective CPU ranges
UNIT_NAME_1="${UNIT_NAME_1:-expt3_1}"
UNIT_NAME_2="${UNIT_NAME_2:-expt3_2}"
UNIT_NAME_3="${UNIT_NAME_3:-expt3_3}"
UNIT_NAME_4="${UNIT_NAME_4:-expt3_4}"

TARGET_CPU_1="${TARGET_CPU_1:-0-9}"     # CPUs 0-9 for cgroup 1
TARGET_CPU_2="${TARGET_CPU_2:-10-19}"   # CPUs 10-19 for cgroup 2
TARGET_CPU_3="${TARGET_CPU_3:-20-29}"   # CPUs 20-29 for cgroup 3
TARGET_CPU_4="${TARGET_CPU_4:-30-39}"   # CPUs 30-39 for cgroup 4

command -v mpstat >/dev/null || { echo "mpstat not found (install 'sysstat')"; exit 1; }

# Cleanup function
cleanup() {
  echo "Cleaning up..."
  "$CGROUP_CLI" stop "$UNIT_NAME_1" || true
  "$CGROUP_CLI" stop "$UNIT_NAME_2" || true
  "$CGROUP_CLI" stop "$UNIT_NAME_3" || true
  "$CGROUP_CLI" stop "$UNIT_NAME_4" || true
}

trap cleanup EXIT

printf "=== Experiment 3: 4 cgroups, 10 threads each, 10 CPUs each ===\n"
printf "Starting workloads:\n"

# Start all 4 cgroups
printf "  Cgroup 1: %s on CPUs %s\n" "$UNIT_NAME_1" "$TARGET_CPU_1"
"$CGROUP_CLI" start "$UNIT_NAME_1" "$TARGET_CPU_1" 10

printf "  Cgroup 2: %s on CPUs %s\n" "$UNIT_NAME_2" "$TARGET_CPU_2"
"$CGROUP_CLI" start "$UNIT_NAME_2" "$TARGET_CPU_2" 10

printf "  Cgroup 3: %s on CPUs %s\n" "$UNIT_NAME_3" "$TARGET_CPU_3"
"$CGROUP_CLI" start "$UNIT_NAME_3" "$TARGET_CPU_3" 10

printf "  Cgroup 4: %s on CPUs %s\n" "$UNIT_NAME_4" "$TARGET_CPU_4"
"$CGROUP_CLI" start "$UNIT_NAME_4" "$TARGET_CPU_4" 10

printf "\nMonitoring. Expect load distributed across 4 CPU groups. Press Ctrl+C to stop.\n\n"

# Monitor
"$CGROUP_CLI" monitor
