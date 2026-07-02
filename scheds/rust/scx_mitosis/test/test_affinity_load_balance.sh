#!/bin/bash
# Test that demonstrates load balancing for affinitized tasks.
#
# Strategy:
# 1. Start scx_mitosis in CellManager mode with an empty managed parent
# 2. Create multiple CPU-bound tasks in the root cgroup (cell 0 has all CPUs)
# 3. Use taskset to restrict each task's affinity to a subset of CPUs
# 4. This triggers the affinity violation path in select_cpu/enqueue
# 5. Dynamic affinity selection should spread tasks across allowed CPUs
#
# Tests both:
# - CPU-bound tasks (no wakeups) - tests enqueue() redistribution
# - Sleep/wake tasks (frequent wakeups) - tests select_cpu() redistribution

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuration (override via environment variables)
NUM_WORKERS="${NUM_WORKERS:-8}"              # Number of CPU-bound worker tasks
AFFINITY_CPUS="${AFFINITY_CPUS:-0-3}"       # CPU mask for all workers (subset of cell CPUs)
WORK_DURATION="${WORK_DURATION:-5}"         # Seconds to run workload
SAMPLE_INTERVAL="${SAMPLE_INTERVAL:-0.5}"   # Seconds between CPU utilization samples
WORKLOAD_TYPE="${1:-both}"                  # "cpu-bound", "wakeup-heavy", or "both"
SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP_BASE="/sys/fs/cgroup/test.slice"
SCHED_PID=""

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

# Parse CPU range into array
parse_cpu_range() {
    local range="$1"
    local cpus=()
    IFS=',' read -ra parts <<< "$range"
    for part in "${parts[@]}"; do
        if [[ "$part" == *-* ]]; then
            local start="${part%-*}"
            local end="${part#*-}"
            for ((i=start; i<=end; i++)); do
                cpus+=("$i")
            done
        else
            cpus+=("$part")
        fi
    done
    echo "${cpus[@]}"
}

CPUS=($(parse_cpu_range "$AFFINITY_CPUS"))
NUM_CPUS=${#CPUS[@]}
TOTAL_SYSTEM_CPUS=$(nproc)

# Verify we have more CPUs than the affinity mask
if [ "$TOTAL_SYSTEM_CPUS" -le "$NUM_CPUS" ]; then
    echo -e "${RED}Need more system CPUs than affinity CPUs to test imbalance${NC}"
    echo -e "${RED}System has $TOTAL_SYSTEM_CPUS CPUs, affinity is $NUM_CPUS CPUs${NC}"
    exit 1
fi

# Check scheduler binary availability
if [[ ! -x "$SCHEDULER_BIN" ]]; then
    echo -e "${RED}Scheduler binary not found: $SCHEDULER_BIN${NC}"
    echo -e "${RED}Please build with: cargo build --release -p scx_mitosis${NC}"
    exit 1
fi

if [[ ! -f "/sys/kernel/sched_ext/state" ]]; then
    echo -e "${RED}sched_ext not available (missing /sys/kernel/sched_ext/state)${NC}"
    exit 1
fi

WORKER_PIDS=()

cleanup() {
    echo -e "\n${YELLOW}Cleanup...${NC}"
    for pid in "${WORKER_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    if [[ -n "$SCHED_PID" ]]; then
        kill -INT "$SCHED_PID" 2>/dev/null || true
        wait "$SCHED_PID" 2>/dev/null || true
    else
        pkill -9 scx_mitosis 2>/dev/null || true
    fi
    if [[ -d "$CGROUP_BASE" ]]; then
        rmdir "$CGROUP_BASE" 2>/dev/null || true
    fi
    wait 2>/dev/null || true
}

trap cleanup EXIT INT TERM

start_scheduler() {
    mkdir -p "$CGROUP_BASE"
    if ! grep -q "cpu" "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
        echo "+cpu" > "$CGROUP_BASE/cgroup.subtree_control"
    fi

    local scheduler_args=("--cell-parent-cgroup" "/test.slice")
    if [[ -n "${SCX_MITOSIS_ARGS:-}" ]]; then
        # shellcheck disable=SC2206
        local extra_args=( ${SCX_MITOSIS_ARGS} )
        scheduler_args+=("${extra_args[@]}")
    fi

    "$SCHEDULER_BIN" "${scheduler_args[@]}" > /tmp/scx_mitosis_affinity.log 2>&1 &
    SCHED_PID=$!
    sleep 3

    if ! ps -p "$SCHED_PID" > /dev/null 2>&1; then
        echo -e "${RED}Failed to start scx_mitosis${NC}"
        cat /tmp/scx_mitosis_affinity.log
        exit 1
    fi

    if [[ "$(cat /sys/kernel/sched_ext/state 2>/dev/null)" != "enabled" ]]; then
        echo -e "${RED}sched_ext did not enable${NC}"
        cat /tmp/scx_mitosis_affinity.log
        exit 1
    fi
}

# Get CPU utilization for specific CPUs
get_cpu_utils() {
    local prev_stats=()
    local curr_stats=()

    for cpu in "${CPUS[@]}"; do
        local line=$(grep "^cpu$cpu " /proc/stat)
        prev_stats+=("$line")
    done

    sleep "$SAMPLE_INTERVAL"

    local utils=()
    for i in "${!CPUS[@]}"; do
        local cpu="${CPUS[$i]}"
        local prev="${prev_stats[$i]}"
        local curr=$(grep "^cpu$cpu " /proc/stat)

        read -r _ p_user p_nice p_sys p_idle p_iowait p_irq p_softirq p_steal _ _ <<< "$prev"
        read -r _ c_user c_nice c_sys c_idle c_iowait c_irq c_softirq c_steal _ _ <<< "$curr"

        local p_total=$((p_user + p_nice + p_sys + p_idle + p_iowait + p_irq + p_softirq + p_steal))
        local c_total=$((c_user + c_nice + c_sys + c_idle + c_iowait + c_irq + c_softirq + c_steal))
        local p_idle_total=$((p_idle + p_iowait))
        local c_idle_total=$((c_idle + c_iowait))
        local total_diff=$((c_total - p_total))
        local idle_diff=$((c_idle_total - p_idle_total))

        if [ "$total_diff" -gt 0 ]; then
            local util=$(( (total_diff - idle_diff) * 100 / total_diff ))
        else
            local util=0
        fi
        utils+=("$util")
    done

    echo "${utils[@]}"
}

run_test() {
    local test_type="$1"
    local test_desc="$2"

    WORKER_PIDS=()

    echo -e "${YELLOW}========================================${NC}"
    echo -e "${YELLOW}TEST: $test_desc${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "Workers: $NUM_WORKERS"
    echo -e "Task affinity: $AFFINITY_CPUS ($NUM_CPUS CPUs)"
    echo -e "System CPUs: $TOTAL_SYSTEM_CPUS"
    echo -e "Duration: ${WORK_DURATION}s"
    echo ""

    echo -e "${GREEN}Mode: dynamic affinity CPU selection enabled${NC}"
    echo ""

    echo -e "${YELLOW}Spawning $NUM_WORKERS workers ($test_type)...${NC}"

    for i in $(seq 1 $NUM_WORKERS); do
        if [ "$test_type" = "cpu-bound" ]; then
            # CPU-bound: tests enqueue() path (no wakeups)
            taskset -c "$AFFINITY_CPUS" yes > /dev/null 2>&1 &
        else
            # Wakeup-heavy: tests select_cpu() path (frequent wakeups)
            taskset -c "$AFFINITY_CPUS" bash -c '
                while true; do
                    for ((j=0; j<5000; j++)); do :; done
                    sleep 0.001
                done
            ' &
        fi
        WORKER_PIDS+=($!)
    done

    echo -e "${GREEN}Workers started: ${WORKER_PIDS[*]}${NC}"
    echo ""

    sleep 1

    echo -e "${YELLOW}Collecting CPU utilization samples...${NC}"
    echo ""

    SAMPLES=()
    NUM_SAMPLES=$((WORK_DURATION * 2))

    printf "%-10s" "Sample"
    for cpu in "${CPUS[@]}"; do
        printf "%-10s" "CPU$cpu"
    done
    printf "%-12s\n" "Std Dev"
    echo "--------------------------------------------------------------"

    for s in $(seq 1 $NUM_SAMPLES); do
        utils=($(get_cpu_utils))
        SAMPLES+=("${utils[*]}")

        sum=0
        for u in "${utils[@]}"; do
            sum=$((sum + u))
        done
        mean=$((sum / NUM_CPUS))

        sq_diff_sum=0
        for u in "${utils[@]}"; do
            diff=$((u - mean))
            sq_diff_sum=$((sq_diff_sum + diff * diff))
        done
        variance=$((sq_diff_sum / NUM_CPUS))
        stddev=0
        if [ "$variance" -gt 0 ]; then
            stddev=$(echo "scale=1; sqrt($variance)" | bc)
        fi

        printf "%-10s" "$s"
        for u in "${utils[@]}"; do
            if [ "$u" -gt 80 ]; then
                printf "${RED}%-10s${NC}" "${u}%"
            elif [ "$u" -gt 50 ]; then
                printf "${YELLOW}%-10s${NC}" "${u}%"
            elif [ "$u" -gt 20 ]; then
                printf "${GREEN}%-10s${NC}" "${u}%"
            else
                printf "%-10s" "${u}%"
            fi
        done
        printf "%-12s\n" "$stddev"
    done

    echo ""

    # Calculate averages
    declare -a AVG_UTILS
    for i in "${!CPUS[@]}"; do
        sum=0
        count=0
        for sample in "${SAMPLES[@]}"; do
            vals=($sample)
            sum=$((sum + vals[i]))
            count=$((count + 1))
        done
        if [ "$count" -gt 0 ]; then
            AVG_UTILS[$i]=$((sum / count))
        else
            AVG_UTILS[$i]=0
        fi
    done

    echo "Average CPU Utilization:"
    for i in "${!CPUS[@]}"; do
        cpu="${CPUS[$i]}"
        avg="${AVG_UTILS[$i]}"
        bar=""
        for ((b=0; b<avg/5; b++)); do
            bar="${bar}#"
        done
        printf "  CPU%-3s: %3d%% %s\n" "$cpu" "$avg" "$bar"
    done

    sum=0
    max_util=0
    min_util=100
    for u in "${AVG_UTILS[@]}"; do
        sum=$((sum + u))
        [ "$u" -gt "$max_util" ] && max_util=$u
        [ "$u" -lt "$min_util" ] && min_util=$u
    done
    mean=$((sum / NUM_CPUS))
    spread=$((max_util - min_util))

    sq_diff_sum=0
    for u in "${AVG_UTILS[@]}"; do
        diff=$((u - mean))
        sq_diff_sum=$((sq_diff_sum + diff * diff))
    done
    variance=$((sq_diff_sum / NUM_CPUS))
    final_stddev=$(echo "scale=1; sqrt($variance)" | bc 2>/dev/null || echo "0")

    echo ""
    echo "Balance Metrics:"
    echo "  Mean utilization: ${mean}%"
    echo "  Max-Min spread:   ${spread}%"
    echo "  Std deviation:    ${final_stddev}%"
    echo ""

    if [ "$MODE" = "legacy" ]; then
        echo -e "${BLUE}Mode: LEGACY${NC}"
        if [ "$spread" -gt 50 ]; then
            echo -e "${RED}HIGH IMBALANCE DETECTED!${NC}"
        elif [ "$spread" -gt 25 ]; then
            echo -e "${YELLOW}Moderate imbalance detected.${NC}"
        else
            echo -e "${GREEN}Load appears balanced.${NC}"
        fi
    else
        echo -e "${GREEN}Mode: DYNAMIC${NC}"
        if [ "$spread" -lt 30 ]; then
            echo -e "${GREEN}Load is well balanced!${NC}"
        else
            echo -e "${YELLOW}Some imbalance remains (spread: ${spread}%)${NC}"
        fi
    fi
    echo ""

    # Cleanup workers for this test
    for pid in "${WORKER_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    sleep 1
    WORKER_PIDS=()
}

# Run tests based on workload type
start_scheduler

case "$WORKLOAD_TYPE" in
    cpu-bound)
        run_test "cpu-bound" "CPU-bound tasks (tests enqueue() path)"
        ;;
    wakeup-heavy)
        run_test "wakeup-heavy" "Wakeup-heavy tasks (tests select_cpu() path)"
        ;;
    both)
        run_test "cpu-bound" "CPU-bound tasks (tests enqueue() path)"
        echo ""
        sleep 2
        run_test "wakeup-heavy" "Wakeup-heavy tasks (tests select_cpu() path)"
        ;;
    *)
        echo "Usage: $0 [cpu-bound|wakeup-heavy|both]"
        exit 1
        ;;
esac

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}TEST COMPLETE${NC}"
echo -e "${YELLOW}========================================${NC}"
