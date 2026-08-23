#!/bin/bash
#
# Smoke test for scx_mitosis --cpu-controller-disabled rollout gating.
#
# The scheduler should:
# - fail when the managed parent cgroup lacks +cpu and the rollout flag is absent
# - use disabled-controller fallback when the parent lacks +cpu and the flag is set
# - stay on the normal cgroup path when the parent has +cpu, even if the flag is set

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP_BASE="/sys/fs/cgroup/scx_mitosis_cpu_controller_disabled.$$"
DISABLED_PARENT="$CGROUP_BASE/disabled_parent"
ENABLED_PARENT="$CGROUP_BASE/enabled_parent"
LOG_DIR="/tmp/scx_mitosis_cpu_controller_disabled.$$"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCHED_PID=""

log_info() {
	echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
	echo -e "${RED}[ERROR]${NC} $1" >&2
}

stop_scheduler() {
	if [[ -n "$SCHED_PID" ]]; then
		kill -INT "$SCHED_PID" 2>/dev/null || true
		wait "$SCHED_PID" 2>/dev/null || true
		SCHED_PID=""
	fi
}

cleanup() {
	echo -e "\n${YELLOW}Cleanup...${NC}"
	stop_scheduler
	rmdir "$DISABLED_PARENT" 2>/dev/null || true
	rmdir "$ENABLED_PARENT" 2>/dev/null || true
	rmdir "$CGROUP_BASE" 2>/dev/null || true
	rm -rf "$LOG_DIR"
}

trap cleanup EXIT INT TERM

cgroup_arg() {
	local cgroup="$1"

	echo "${cgroup#/sys/fs/cgroup}"
}

check_scheduler() {
	local log_file="$1"

	if [[ -z "$SCHED_PID" ]] || ! kill -0 "$SCHED_PID" 2>/dev/null; then
		log_error "scx_mitosis exited unexpectedly"
		cat "$log_file" >&2
		exit 1
	fi
}

check_sched_ext_enabled() {
	local log_file="$1"

	if [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" != "enabled" ]]; then
		log_error "sched_ext did not enable"
		cat "$log_file" >&2
		exit 1
	fi
}

start_scheduler() {
	local parent="$1"
	local log_file="$2"
	shift 2

	log_info "Starting scx_mitosis for $(cgroup_arg "$parent") $*"
	"$SCHEDULER_BIN" \
		--cell-parent-cgroup "$(cgroup_arg "$parent")" \
		"$@" \
		> "$log_file" 2>&1 &
	SCHED_PID=$!
	sleep 3
	check_scheduler "$log_file"
	check_sched_ext_enabled "$log_file"
}

expect_startup_failure_without_flag() {
	local log_file="$LOG_DIR/missing_cpu_without_flag.log"
	local status

	log_info "Checking startup fails when parent lacks +cpu and flag is absent"
	set +e
	timeout --signal=INT --kill-after=5s 5s \
		"$SCHEDULER_BIN" \
		--cell-parent-cgroup "$(cgroup_arg "$DISABLED_PARENT")" \
		> "$log_file" 2>&1
	status=$?
	set -e

	if [[ "$status" -eq 0 || "$status" -eq 124 ]]; then
		log_error "scx_mitosis did not fail fast when parent lacked +cpu and flag was absent"
		cat "$log_file" >&2
		exit 1
	fi

	if ! grep -q "cpu controller is not enabled" "$log_file"; then
		log_error "startup failure did not report missing cpu controller"
		cat "$log_file" >&2
		exit 1
	fi
}

expect_fallback_with_flag() {
	local log_file="$LOG_DIR/missing_cpu_with_flag.log"

	log_info "Checking fallback enables when parent lacks +cpu and flag is set"
	start_scheduler "$DISABLED_PARENT" "$log_file" --cpu-controller-disabled

	if ! grep -q "cpu_controller_disabled=true" "$log_file"; then
		log_error "disabled-controller fallback was not enabled"
		cat "$log_file" >&2
		exit 1
	fi

	stop_scheduler
}

expect_normal_path_with_cpu_and_flag() {
	local log_file="$LOG_DIR/cpu_enabled_with_flag.log"

	log_info "Checking fallback stays disabled when parent has +cpu and flag is set"
	start_scheduler "$ENABLED_PARENT" "$log_file" --cpu-controller-disabled

	if grep -q "cpu_controller_disabled=true" "$log_file"; then
		log_error "disabled-controller fallback was enabled while parent had +cpu"
		cat "$log_file" >&2
		exit 1
	fi

	stop_scheduler
}

if [[ "$EUID" -ne 0 ]]; then
	log_error "Must run as root"
	exit 1
fi

if [[ ! -x "$SCHEDULER_BIN" ]]; then
	log_error "Scheduler binary not found: $SCHEDULER_BIN"
	log_error "Please build with: cargo build --release -p scx_mitosis"
	exit 1
fi

if [[ ! -f "/sys/kernel/sched_ext/state" ]]; then
	log_error "sched_ext not available (missing /sys/kernel/sched_ext/state)"
	exit 1
fi

if [[ ! -f "/sys/fs/cgroup/cgroup.controllers" ]]; then
	log_error "/sys/fs/cgroup is not a cgroupv2 mount"
	exit 1
fi

if ! grep -qw "cpu" /sys/fs/cgroup/cgroup.controllers; then
	log_error "cpu controller is not available in /sys/fs/cgroup/cgroup.controllers"
	exit 1
fi

mkdir -p "$LOG_DIR"
mkdir -p "$CGROUP_BASE"

echo "+cpu" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
if ! grep -qw "cpu" "$CGROUP_BASE/cgroup.controllers"; then
	log_error "cpu controller is not available to temporary test cgroup"
	exit 1
fi

echo "+cpu" > "$CGROUP_BASE/cgroup.subtree_control"
mkdir -p "$DISABLED_PARENT" "$ENABLED_PARENT"
echo "+cpu" > "$ENABLED_PARENT/cgroup.subtree_control"

expect_startup_failure_without_flag
expect_fallback_with_flag
expect_normal_path_with_cpu_and_flag

echo -e "${GREEN}PASS${NC}: scx_mitosis cpu-controller-disabled gating smoke test passed"
