#!/bin/bash
#
# Minimal reproducer for the scx_mitosis LLC drain affinity failure.
#
# The script creates two child cgroups under a temporary parent:
# - mitosis_victim: high wakeup-rate burst workers pinned to the victim cell's
#   expected initial CPU range.
# - mitosis_pressure: CPU-bound pressure workers.
#
# scx_mitosis is started with LLC-awareness and demand rebalancing. Rebalancing
# moves the victim cell away from the victim workers' affinity mask while stale
# LLC DSQ work can remain on the old LLCs. The current failure usually appears
# as a runnable stall of a mito_victim thread.
#
# Only SCHEDULER_BIN is intended to be overridden.

set -euo pipefail

SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"

RUN_SECS=45
STARTUP_SECS=60
SETTLE_SECS=5
VICTIM_WORKERS=512
PRESSURE_WORKERS="$(nproc)"
VICTIM_SPIN_ITERS=20000
VICTIM_WAKE_NS=50000
PRESSURE_SPIN_ITERS=200000

CGROUP_BASE="/sys/fs/cgroup/scx_mitosis_repro.$$"
VICTIM_NAME="mitosis_victim"
PRESSURE_NAME="mitosis_pressure"
LOG_FILE="/tmp/scx_mitosis_llc_drain_affinity.log"
MONITOR_LOG_FILE="/tmp/scx_mitosis_llc_drain_affinity_monitor.log"

SCHED_PID=""
MONITOR_PID=""
WORKER_PIDS=()
TMPDIR=""
HELPER=""

info() {
    echo "[INFO] $1"
}

error() {
    echo "[ERROR] $1" >&2
}

sum_monitor_counter() {
    local field="$1"

    awk -v field="\"$field\"" '
        index($0, field) {
            val = $2
            gsub(/[^0-9]/, "", val)
            if (val != "")
                total += val
        }
        END { print total + 0 }
    ' "$MONITOR_LOG_FILE" 2>/dev/null
}

expand_cpulist() {
    local list="$1"
    local part start end cpu

    IFS=',' read -ra parts <<< "$list"
    for part in "${parts[@]}"; do
        [[ -n "$part" ]] || continue
        if [[ "$part" == *-* ]]; then
            start="${part%-*}"
            end="${part#*-}"
            for ((cpu = start; cpu <= end; cpu++)); do
                echo "$cpu"
            done
        else
            echo "$part"
        fi
    done
}

compress_cpus() {
    local -a cpus=("$@")
    local out="" start prev cpu

    (( ${#cpus[@]} > 0 )) || return 0

    start="${cpus[0]}"
    prev="$start"
    for cpu in "${cpus[@]:1}"; do
        if (( cpu == prev + 1 )); then
            prev="$cpu"
            continue
        fi

        if [[ "$start" == "$prev" ]]; then
            out+="${out:+,}${start}"
        else
            out+="${out:+,}${start}-${prev}"
        fi
        start="$cpu"
        prev="$cpu"
    done

    if [[ "$start" == "$prev" ]]; then
        out+="${out:+,}${start}"
    else
        out+="${out:+,}${start}-${prev}"
    fi
    echo "$out"
}

count_llcs() {
    local seen=""
    local f mask

    for f in /sys/devices/system/cpu/cpu*/cache/index3/shared_cpu_list; do
        [[ -r "$f" ]] || continue
        mask="$(cat "$f")"
        if [[ ",$seen," != *",$mask,"* ]]; then
            seen+="${seen:+,}${mask}"
        fi
    done

    if [[ -z "$seen" ]]; then
        echo 1
    else
        awk -F, '{ print NF }' <<< "$seen"
    fi
}

build_helper() {
    TMPDIR="$(mktemp -d /tmp/scx_mitosis_repro.XXXXXX)"
    HELPER="$TMPDIR/wakeup_storm"

    cat > "$TMPDIR/wakeup_storm.c" <<'EOF'
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t stop;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
static unsigned long epoch;
static int started;

struct worker_args {
	unsigned long spin_iters;
	const char *name;
	int burst;
};

static void handle_signal(int sig)
{
	(void)sig;
	stop = 1;
	pthread_cond_broadcast(&cond);
}

static void spin_for(unsigned long spin_iters)
{
	for (volatile unsigned long i = 0; i < spin_iters; i++)
		;
}

static void *worker_main(void *arg)
{
	struct worker_args *args = arg;
	unsigned long seen = 0;

	prctl(PR_SET_NAME, args->name, 0, 0, 0);
	pthread_mutex_lock(&lock);
	started++;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&lock);

	while (!stop) {
		if (args->burst) {
			pthread_mutex_lock(&lock);
			while (seen == epoch && !stop)
				pthread_cond_wait(&cond, &lock);
			seen = epoch;
			pthread_mutex_unlock(&lock);
			if (stop)
				break;
		}
		spin_for(args->spin_iters);
	}

	return NULL;
}

static void sleep_ns(long period_ns)
{
	struct timespec ts = {
		.tv_sec = period_ns / 1000000000L,
		.tv_nsec = period_ns % 1000000000L,
	};

	while (nanosleep(&ts, &ts) && errno == EINTR && !stop)
		;
}

int main(int argc, char **argv)
{
	const char *mode = argc > 1 ? argv[1] : "burst";
	int workers = argc > 2 ? atoi(argv[2]) : 1;
	unsigned long spin_iters = argc > 3 ? strtoul(argv[3], NULL, 0) : 20000;
	long period_ns = argc > 4 ? strtol(argv[4], NULL, 0) : 50000;
	int burst = !strcmp(mode, "burst");
	pthread_t *threads;
	struct worker_args args = {
		.spin_iters = spin_iters,
		.name = burst ? "mito_victim" : "mito_press",
		.burst = burst,
	};

	if (workers <= 0)
		return 1;

	prctl(PR_SET_NAME, burst ? "mito_victim_ctl" : "mito_press_ctl", 0, 0, 0);
	signal(SIGTERM, handle_signal);
	signal(SIGINT, handle_signal);

	threads = calloc(workers, sizeof(*threads));
	if (!threads)
		return 1;

	for (int i = 0; i < workers; i++) {
		int ret = pthread_create(&threads[i], NULL, worker_main, &args);
		if (ret) {
			errno = ret;
			perror("pthread_create");
			stop = 1;
			workers = i;
			break;
		}
	}

	pthread_mutex_lock(&lock);
	while (started < workers && !stop)
		pthread_cond_wait(&cond, &lock);
	pthread_mutex_unlock(&lock);

	if (burst) {
		while (!stop) {
			sleep_ns(period_ns);
			pthread_mutex_lock(&lock);
			epoch++;
			pthread_cond_broadcast(&cond);
			pthread_mutex_unlock(&lock);
		}
	} else {
		while (!stop)
			pause();
	}

	pthread_mutex_lock(&lock);
	epoch++;
	pthread_cond_broadcast(&cond);
	pthread_mutex_unlock(&lock);

	for (int i = 0; i < workers; i++)
		pthread_join(threads[i], NULL);

	free(threads);
	return 0;
}
EOF

    cc -O2 -Wall -Wextra -pthread -o "$HELPER" "$TMPDIR/wakeup_storm.c"
}

start_in_cgroup() {
    local cg="$1"
    shift

    bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec "$@"' _ "$cg" "$@" &
    WORKER_PIDS+=("$!")
}

cleanup() {
    local pid cg

    set +e
    for pid in "${WORKER_PIDS[@]}"; do
        kill -TERM "$pid" 2>/dev/null || true
    done
    sleep 0.2
    for pid in "${WORKER_PIDS[@]}"; do
        kill -KILL "$pid" 2>/dev/null || true
    done
    for pid in "${WORKER_PIDS[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    if [[ -n "$MONITOR_PID" ]]; then
        kill -INT "$MONITOR_PID" 2>/dev/null || true
        wait "$MONITOR_PID" 2>/dev/null || true
    fi

    if [[ -n "$SCHED_PID" ]]; then
        kill -INT "$SCHED_PID" 2>/dev/null || true
        wait "$SCHED_PID" 2>/dev/null || true
    fi

    for cg in "$CGROUP_BASE/$VICTIM_NAME" "$CGROUP_BASE/$PRESSURE_NAME" "$CGROUP_BASE"; do
        [[ -d "$cg" ]] || continue
        while read -r pid; do
            [[ -n "$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
        done < <(cat "$cg/cgroup.procs" 2>/dev/null || true)
        rmdir "$cg" 2>/dev/null || true
    done

    [[ -n "$TMPDIR" ]] && rm -rf "$TMPDIR"
}

trap cleanup EXIT INT TERM

if [[ "$EUID" -ne 0 ]]; then
    error "Must run as root"
    exit 1
fi

if [[ ! -x "$SCHEDULER_BIN" ]]; then
    error "Scheduler binary not found: $SCHEDULER_BIN"
    error "Build it with: cargo build --release -p scx_mitosis"
    exit 1
fi

if [[ ! -f /sys/kernel/sched_ext/state ]]; then
    error "sched_ext not available"
    exit 1
fi

if [[ "$(cat /sys/kernel/sched_ext/state)" != "disabled" ]]; then
    error "sched_ext is already enabled"
    exit 1
fi

if (( $(count_llcs) < 2 )); then
    error "Need a multi-LLC system"
    exit 1
fi

mapfile -t ONLINE_CPUS < <(expand_cpulist "$(cat /sys/devices/system/cpu/online)")
NR_CPUS="${#ONLINE_CPUS[@]}"
if (( NR_CPUS < 6 )); then
    error "Need at least 6 online CPUs; found $NR_CPUS"
    exit 1
fi

CELL0_COUNT=$((NR_CPUS / 3 + (0 < NR_CPUS % 3 ? 1 : 0)))
CELL1_COUNT=$((NR_CPUS / 3 + (1 < NR_CPUS % 3 ? 1 : 0)))
VICTIM_CPUS=("${ONLINE_CPUS[@]:CELL0_COUNT:CELL1_COUNT}")
VICTIM_CPU_LIST="$(compress_cpus "${VICTIM_CPUS[@]}")"

build_helper
rm -f "$LOG_FILE" "$MONITOR_LOG_FILE"

mkdir -p "$CGROUP_BASE/$VICTIM_NAME"
if ! grep -qw cpu "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
    echo "+cpu" > "$CGROUP_BASE/cgroup.subtree_control"
fi

info "Victim task affinity mask: $VICTIM_CPU_LIST"
info "Starting scx_mitosis"
"$SCHEDULER_BIN" \
    --cell-parent-cgroup "${CGROUP_BASE#/sys/fs/cgroup}" \
    --enable-llc-awareness \
    --enable-rebalancing \
    --dynamic-affinity-cpu-selection \
    --enable-slice-shrinking \
    --rebalance-threshold 1.0 \
    --rebalance-cooldown-s 8 \
    --demand-smoothing 1.0 \
    --monitor-interval-s 1 \
    > "$LOG_FILE" 2>&1 &
SCHED_PID="$!"

sleep 2
if ! ps -p "$SCHED_PID" >/dev/null 2>&1; then
    error "scx_mitosis failed to start"
    cat "$LOG_FILE"
    exit 1
fi

for _ in $(seq 1 "$STARTUP_SECS"); do
    [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" == "enabled" ]] && break
    sleep 1
done

if [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" != "enabled" ]]; then
    error "sched_ext did not enable"
    cat "$LOG_FILE"
    exit 1
fi

mkdir -p "$CGROUP_BASE/$PRESSURE_NAME"
sleep "$SETTLE_SECS"

info "Starting victim workload"
start_in_cgroup "$CGROUP_BASE/$VICTIM_NAME" \
    taskset -c "$VICTIM_CPU_LIST" "$HELPER" burst "$VICTIM_WORKERS" \
    "$VICTIM_SPIN_ITERS" "$VICTIM_WAKE_NS"

sleep 1

info "Starting pressure workload"
start_in_cgroup "$CGROUP_BASE/$PRESSURE_NAME" \
    "$HELPER" pressure "$PRESSURE_WORKERS" "$PRESSURE_SPIN_ITERS" 0

info "Starting stats monitor"
"$SCHEDULER_BIN" --monitor 1 > "$MONITOR_LOG_FILE" 2>&1 &
MONITOR_PID="$!"

sleep 2
if ! ps -p "$MONITOR_PID" >/dev/null 2>&1; then
    error "scx_mitosis monitor failed to start"
    cat "$MONITOR_LOG_FILE"
    exit 1
fi

info "Running for ${RUN_SECS}s"
for _ in $(seq 1 "$RUN_SECS"); do
    sleep 1
    ps -p "$SCHED_PID" >/dev/null 2>&1 || break
done

if ! ps -p "$SCHED_PID" >/dev/null 2>&1; then
    wait "$SCHED_PID" 2>/dev/null || true
    SCHED_PID=""
    if grep -Eq 'runnable task stall \(mito_victim\[[0-9]+\] failed to run|target CPU .* not allowed|affinity' "$LOG_FILE"; then
        info "PASS: reproduced scx_mitosis LLC drain affinity failure"
        grep -En 'runnable task stall \(mito_victim\[[0-9]+\] failed to run|target CPU .* not allowed|affinity' "$LOG_FILE" | tail -10
        exit 0
    fi

    error "scx_mitosis exited, but not with the expected failure"
    tail -200 "$LOG_FILE"
    exit 1
fi

DRAIN_AFFN_CNT="$(sum_monitor_counter drain_affn_cnt)"
if (( DRAIN_AFFN_CNT <= 0 )); then
    error "scx_mitosis survived, but drain_affn_cnt did not increase"
    tail -120 "$LOG_FILE"
    tail -120 "$MONITOR_LOG_FILE"
    exit 1
fi

info "PASS: scx_mitosis survived after exercising drain affinity rescue (drain_affn_cnt=$DRAIN_AFFN_CNT)"
exit 0
