#!/bin/bash
# Validate scx_mitosis debug-event recording through a live sched_ext dump.

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
TRACE_ROOT="/sys/kernel/tracing"
TEST_NAME="scx_mitosis_debug_events_$$"
CGROUP_BASE="/sys/fs/cgroup/$TEST_NAME"
CELL_CGROUP="$CGROUP_BASE/cell"
TRACE_INSTANCE="$TRACE_ROOT/instances/$TEST_NAME"
TRACE_OUTPUT="/tmp/$TEST_NAME.trace"
SCHED_LOG="/tmp/$TEST_NAME.log"

SCHED_PID=""
WORKER_PID=""
TRACE_READER_PID=""
CELL_CGID=""

cleanup() {
	set +e

	if [[ -n "$TRACE_READER_PID" ]]; then
		kill "$TRACE_READER_PID" 2>/dev/null
		wait "$TRACE_READER_PID" 2>/dev/null
	fi

	if [[ -d "$CELL_CGROUP" ]]; then
		echo 1 > "$CELL_CGROUP/cgroup.kill" 2>/dev/null
	fi
	if [[ -n "$WORKER_PID" ]]; then
		wait "$WORKER_PID" 2>/dev/null
	fi

	if [[ -n "$SCHED_PID" ]]; then
		kill -TERM "$SCHED_PID" 2>/dev/null
		for _ in $(seq 1 20); do
			kill -0 "$SCHED_PID" 2>/dev/null || break
			sleep 0.1
		done
		if kill -0 "$SCHED_PID" 2>/dev/null; then
			kill -KILL "$SCHED_PID" 2>/dev/null
		fi
		wait "$SCHED_PID" 2>/dev/null
	fi

	rmdir "$CELL_CGROUP" 2>/dev/null
	rmdir "$CGROUP_BASE" 2>/dev/null
	rmdir "$TRACE_INSTANCE" 2>/dev/null
}

trap cleanup EXIT INT TERM

if [[ "$EUID" -ne 0 ]]; then
	echo "Must run as root" >&2
	exit 1
fi

if [[ ! -x "$SCHEDULER_BIN" ]]; then
	echo "Scheduler binary not found: $SCHEDULER_BIN" >&2
	exit 1
fi

if [[ ! -e /sys/kernel/sched_ext/state ]]; then
	echo "sched_ext is not available" >&2
	exit 1
fi

mkdir "$CGROUP_BASE"
if ! grep -q cpu "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
	echo +cpu > "$CGROUP_BASE/cgroup.subtree_control"
fi

"$SCHEDULER_BIN" \
	--cell-parent-cgroup "/$TEST_NAME" \
	--debug-events \
	> "$SCHED_LOG" 2>&1 &
SCHED_PID=$!
sleep 3

if ! ps -p "$SCHED_PID" > /dev/null 2>&1; then
	echo "scx_mitosis failed to start" >&2
	cat "$SCHED_LOG" >&2
	exit 1
fi

if [[ "$(</sys/kernel/sched_ext/state)" != "enabled" ]]; then
	echo "sched_ext did not enable" >&2
	cat "$SCHED_LOG" >&2
	exit 1
fi

mkdir "$CELL_CGROUP"
CELL_CGID="$(stat -c %i "$CELL_CGROUP")"

bash -c "echo \$\$ > '$CELL_CGROUP/cgroup.procs'; sleep 60 & wait" &
WORKER_PID=$!
sleep 0.5

echo 1 > "$CELL_CGROUP/cgroup.kill"
wait "$WORKER_PID" 2>/dev/null || true
WORKER_PID=""
rmdir "$CELL_CGROUP"
sleep 0.5

mkdir "$TRACE_INSTANCE"
echo 1 > "$TRACE_INSTANCE/events/sched_ext/sched_ext_dump/enable"
cat "$TRACE_INSTANCE/trace_pipe" > "$TRACE_OUTPUT" &
TRACE_READER_PID=$!
sleep 0.1

echo D > /proc/sysrq-trigger
sleep 1

kill "$TRACE_READER_PID" 2>/dev/null || true
wait "$TRACE_READER_PID" 2>/dev/null || true
TRACE_READER_PID=""

for event in CGROUP_INIT INIT_TASK CGROUP_EXIT; do
	if ! grep -Eq "$event[[:space:]]+cgid=$CELL_CGID" "$TRACE_OUTPUT"; then
		echo "Missing debug event for cgroup $CELL_CGID: $event" >&2
		grep "cgid=$CELL_CGID" "$TRACE_OUTPUT" >&2 || true
		exit 1
	fi
done

echo "PASS: captured CGROUP_INIT, INIT_TASK, and CGROUP_EXIT"
echo "Trace: $TRACE_OUTPUT"
