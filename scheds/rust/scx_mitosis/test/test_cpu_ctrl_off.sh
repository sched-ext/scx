#!/bin/bash
# Test for CPU controller OFF affinity violations
#
# Simulates 4 cpusetted containers running workloads.
# Run with: vng -r --user root --cpus 64 -- ./test_cpu_ctrl_off.sh

set -e

CGROUP_ROOT="/sys/fs/cgroup"
TEST_DURATION=10

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

NUM_CPUS=$(nproc)
if [ "$NUM_CPUS" -lt 32 ]; then
    echo -e "${RED}Need at least 32 CPUs (have $NUM_CPUS)${NC}"
    exit 1
fi

STRESS_PIDS=()
CREATED_CGROUPS=()

cleanup() {
    echo -e "\n${YELLOW}Cleanup...${NC}"
    for pid in "${STRESS_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    pkill -9 stress-ng 2>/dev/null || true
    pkill -9 scx_mitosis 2>/dev/null || true

    for ((i=${#CREATED_CGROUPS[@]}-1; i>=0; i--)); do
        cg="${CREATED_CGROUPS[$i]}"
        if [ -d "$cg" ]; then
            cat "$cg/cgroup.procs" 2>/dev/null | while read pid; do
                echo "$pid" > "$CGROUP_ROOT/cgroup.procs" 2>/dev/null || true
            done
            rmdir "$cg" 2>/dev/null || true
        fi
    done
}

trap cleanup EXIT INT TERM

run_test() {
    local cpu_ctrl=$1

    echo -e "\n${YELLOW}============================================${NC}"
    echo -e "${YELLOW}TEST: CPU controller $cpu_ctrl${NC}"
    echo -e "${YELLOW}============================================${NC}"

    STRESS_PIDS=()
    CREATED_CGROUPS=()

    # Set CPU controller state
    if [ "$cpu_ctrl" = "ON" ]; then
        echo "+cpu +cpuset" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
    else
        echo "-cpu +cpuset" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
    fi
    echo "Root controllers: $(cat $CGROUP_ROOT/cgroup.subtree_control)"

    # Create 4 cpusetted containers
    echo -e "${YELLOW}Creating 4 cpusetted containers...${NC}"
    for i in 0 1 2 3; do
        cg="$CGROUP_ROOT/container$i"
        mkdir -p "$cg"
        CREATED_CGROUPS+=("$cg")

        # Each container gets 4 CPUs
        local start=$((i * 4))
        local end=$((start + 3))
        echo "$start-$end" > "$cg/cpuset.cpus"
        echo "  container$i: cpuset=$start-$end"
    done

    # Start workloads BEFORE mitosis
    echo -e "${YELLOW}Starting workloads in containers...${NC}"
    for i in 0 1 2 3; do
        cg="$CGROUP_ROOT/container$i"
        # Start stress-ng, then move its PIDs to the cgroup
        stress-ng --cpu 4 --timeout $((TEST_DURATION + 15))s --quiet &
        local stress_pid=$!
        STRESS_PIDS+=("$stress_pid")
        # Move the stress-ng process and all its children to the cgroup
        echo "$stress_pid" > "$cg/cgroup.procs" 2>/dev/null || true
        # Wait briefly for children to spawn
        sleep 0.2
        # Move any children that spawned
        for child in $(pgrep -P "$stress_pid" 2>/dev/null); do
            echo "$child" > "$cg/cgroup.procs" 2>/dev/null || true
        done
    done
    echo "  Started stress-ng in all 4 containers"
    sleep 1

    # Verify workloads are in the right cgroups with correct cpusets
    echo "  Verifying cgroup placement and cpuset confinement:"
    for i in 0 1 2 3; do
        cg="$CGROUP_ROOT/container$i"
        procs=$(cat "$cg/cgroup.procs" 2>/dev/null | wc -l)
        cpus=$(cat "$cg/cpuset.cpus" 2>/dev/null)
        effective=$(cat "$cg/cpuset.cpus.effective" 2>/dev/null)
        # Check actual CPU affinity of first process
        first_pid=$(cat "$cg/cgroup.procs" 2>/dev/null | head -1)
        if [ -n "$first_pid" ]; then
            affinity=$(taskset -p "$first_pid" 2>/dev/null | grep -oP 'mask: \K[0-9a-f]+')
        fi
        echo "    container$i: $procs procs, cpuset=$cpus, effective=$effective, affinity=$affinity"
    done

    # Start mitosis
    echo -e "${YELLOW}Starting mitosis...${NC}"
    local stats_file="/tmp/mitosis_${cpu_ctrl}.log"
    RUST_LOG=trace ./target/release/scx_mitosis 2>&1 > "$stats_file" &
    local mitosis_pid=$!
    STRESS_PIDS+=("$mitosis_pid")

    echo -e "${YELLOW}Running for ${TEST_DURATION}s...${NC}"
    sleep $TEST_DURATION

    echo -e "${YELLOW}Stopping...${NC}"
    kill -INT "$mitosis_pid" 2>/dev/null || true
    sleep 1

    for pid in "${STRESS_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    pkill -9 stress-ng 2>/dev/null || true
    STRESS_PIDS=()
    wait 2>/dev/null || true

    # Results
    echo -e "\n${YELLOW}Results for CPU controller $cpu_ctrl:${NC}"

    local total_lines=$(grep "Total Decisions" "$stats_file" | tail -5)
    if [ -z "$total_lines" ]; then
        echo -e "${RED}No stats - check log${NC}"
        tail -20 "$stats_file"
        echo "99.9"
        return 1
    fi

    local violations=$(echo "$total_lines" | grep -oP 'V:\s*\K[0-9.]+' | \
        awk '{sum+=$1; count++} END {if(count>0) printf "%.1f", sum/count; else print "0.0"}')

    echo "  Affinity violations (avg): ${violations}%"
    echo "  Last 5 Total Decisions lines:"
    echo "$total_lines" | sed 's/^/    /'

    echo "  Per-cell stats (all non-zero cells):"
    grep "Cell " "$stats_file" | grep -v "Cell   0:" | tail -20 | sed 's/^/    /' || echo "    (only cell 0 found)"

    echo "  CELL cpumask assignments:"
    grep "CELL\[" "$stats_file" | tail -10 | sed 's/^/    /' || echo "    (none found)"

    # Check if cells were properly created (not just cell 0)
    local num_cells=$(grep "CELL\[" "$stats_file" | grep -v "CELL\[0\]" | wc -l)
    if [ "$num_cells" -eq 0 ]; then
        echo -e "  ${RED}WARNING: Only Cell 0 exists - cpusets not honored!${NC}"
    else
        echo -e "  ${GREEN}Cells 1+ created for cpusetted containers${NC}"
    fi

    # Cleanup
    for ((i=${#CREATED_CGROUPS[@]}-1; i>=0; i--)); do
        cg="${CREATED_CGROUPS[$i]}"
        if [ -d "$cg" ]; then
            cat "$cg/cgroup.procs" 2>/dev/null | while read pid; do
                echo "$pid" > "$CGROUP_ROOT/cgroup.procs" 2>/dev/null || true
            done
            rmdir "$cg" 2>/dev/null || true
        fi
    done
    CREATED_CGROUPS=()

    # Return both violations and cell count (cell count as second line)
    echo "$violations"
    echo "$num_cells"
}

run_move_test() {
    local cpu_ctrl=$1

    echo -e "\n${YELLOW}============================================${NC}"
    echo -e "${YELLOW}MOVE TEST: CPU controller $cpu_ctrl${NC}"
    echo -e "${YELLOW}============================================${NC}"

    STRESS_PIDS=()
    CREATED_CGROUPS=()

    # Set CPU controller state
    if [ "$cpu_ctrl" = "ON" ]; then
        echo "+cpu +cpuset" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
    else
        echo "-cpu +cpuset" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
    fi
    echo "Root controllers: $(cat $CGROUP_ROOT/cgroup.subtree_control)"

    # Create 2 cpusetted containers with non-overlapping CPUs
    echo -e "${YELLOW}Creating 2 cpusetted containers...${NC}"
    for i in 0 1; do
        cg="$CGROUP_ROOT/move_container$i"
        mkdir -p "$cg"
        CREATED_CGROUPS+=("$cg")
        local start=$((i * 8))
        local end=$((start + 7))
        echo "$start-$end" > "$cg/cpuset.cpus"
        echo "  move_container$i: cpuset=$start-$end"
    done

    # Start mitosis FIRST
    echo -e "${YELLOW}Starting mitosis...${NC}"
    local stats_file="/tmp/mitosis_move_${cpu_ctrl}.log"
    RUST_LOG=trace ./target/release/scx_mitosis 2>&1 > "$stats_file" &
    local mitosis_pid=$!
    STRESS_PIDS+=("$mitosis_pid")
    sleep 2  # Let mitosis initialize and timer run

    # Start workloads in container0
    echo -e "${YELLOW}Starting workloads in container0...${NC}"
    local cg0="$CGROUP_ROOT/move_container0"
    local cg1="$CGROUP_ROOT/move_container1"

    for j in 1 2 3 4; do
        stress-ng --cpu 2 --timeout 30s --quiet &
        local stress_pid=$!
        STRESS_PIDS+=("$stress_pid")
        echo "$stress_pid" > "$cg0/cgroup.procs" 2>/dev/null || true
        sleep 0.1
        for child in $(pgrep -P "$stress_pid" 2>/dev/null); do
            echo "$child" > "$cg0/cgroup.procs" 2>/dev/null || true
        done
    done

    echo "  Workloads in container0:"
    echo "    procs: $(cat $cg0/cgroup.procs 2>/dev/null | wc -l)"
    echo "    cpuset: $(cat $cg0/cpuset.cpus)"

    # Let workloads run for a bit to establish baseline
    echo -e "${YELLOW}Running for 3s before move...${NC}"
    sleep 3

    # Get pre-move stats - count lines in stats file to mark position
    local pre_move_line_count=$(wc -l < "$stats_file")
    local pre_move_lines=$(grep "Total Decisions" "$stats_file" | tail -3)
    local pre_viol=$(echo "$pre_move_lines" | grep -oP 'V:\s*\K[0-9.]+' | tail -1)
    echo "  Pre-move violations: ${pre_viol}%"

    # Check pre-move cell activity (Cell 1 = container0 cpuset 0-7, Cell 2 = container1 cpuset 8-15)
    local pre_cell1=$(grep "Cell   1:" "$stats_file" | tail -3 | grep -oP 'Cell   1:\s+\K[0-9]+' | awk '{sum+=$1} END {print sum+0}')
    local pre_cell2=$(grep "Cell   2:" "$stats_file" | tail -3 | grep -oP 'Cell   2:\s+\K[0-9]+' | awk '{sum+=$1} END {print sum+0}')
    echo "  Pre-move cell activity: Cell1=$pre_cell1 Cell2=$pre_cell2"

    # MOVE all workloads from container0 to container1
    echo -e "${YELLOW}Moving ALL workloads from container0 to container1...${NC}"
    for pid in $(cat "$cg0/cgroup.procs" 2>/dev/null); do
        echo "$pid" > "$cg1/cgroup.procs" 2>/dev/null || true
    done

    echo "  After move:"
    echo "    container0 procs: $(cat $cg0/cgroup.procs 2>/dev/null | wc -l)"
    echo "    container1 procs: $(cat $cg1/cgroup.procs 2>/dev/null | wc -l)"
    echo "    container1 cpuset: $(cat $cg1/cpuset.cpus)"

    # Run for a while after move to see if violations spike
    echo -e "${YELLOW}Running for 5s after move...${NC}"
    sleep 5

    # Stop mitosis
    echo -e "${YELLOW}Stopping...${NC}"
    kill -INT "$mitosis_pid" 2>/dev/null || true
    sleep 1

    for pid in "${STRESS_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    pkill -9 stress-ng 2>/dev/null || true
    STRESS_PIDS=()
    wait 2>/dev/null || true

    # Results - look at post-move stats
    echo -e "\n${YELLOW}Results for MOVE TEST CPU controller $cpu_ctrl:${NC}"

    # Get all stats after the move (last 5 lines)
    local post_move_lines=$(grep "Total Decisions" "$stats_file" | tail -5)
    if [ -z "$post_move_lines" ]; then
        echo -e "${RED}No stats - check log${NC}"
        tail -20 "$stats_file"
        echo "99.9"
        return 1
    fi

    local post_viol=$(echo "$post_move_lines" | grep -oP 'V:\s*\K[0-9.]+' | \
        awk '{sum+=$1; count++} END {if(count>0) printf "%.1f", sum/count; else print "0.0"}')

    echo "  Post-move affinity violations (avg): ${post_viol}%"
    echo "  Last 5 stat lines after move:"
    echo "$post_move_lines" | sed 's/^/    /'

    # Check post-move cell activity - only look at lines AFTER the move
    # Use tail to get stats from after the move (last 3 samples)
    local post_cell1=$(grep "Cell   1:" "$stats_file" | tail -3 | grep -oP 'Cell   1:\s+\K[0-9]+' | awk '{sum+=$1} END {print sum+0}')
    local post_cell2=$(grep "Cell   2:" "$stats_file" | tail -3 | grep -oP 'Cell   2:\s+\K[0-9]+' | awk '{sum+=$1} END {print sum+0}')
    echo "  Post-move cell activity: Cell1=$post_cell1 Cell2=$post_cell2"

    # Verify move worked: Cell 2 should have MORE activity than Cell 1 after move
    # (Before move, Cell 1 had activity, Cell 2 had none)
    local move_detected=0
    if [ "$post_cell2" -gt "$post_cell1" ] 2>/dev/null; then
        echo -e "  ${GREEN}Move detected: Cell2 ($post_cell2) > Cell1 ($post_cell1) after move${NC}"
        move_detected=1
    elif [ "$post_cell2" -gt 0 ] 2>/dev/null && [ "$pre_cell2" -eq 0 ] 2>/dev/null; then
        echo -e "  ${GREEN}Move detected: Cell2 activity appeared after move${NC}"
        move_detected=1
    else
        echo -e "  ${RED}Move NOT detected: Cell2=$post_cell2 Cell1=$post_cell1 (expected Cell2 > Cell1)${NC}"
    fi

    echo "  CELL cpumask assignments:"
    grep "CELL\[" "$stats_file" | tail -6 | sed 's/^/    /' || echo "    (none found)"

    # Check if cells were properly created (not just cell 0)
    local num_cells=$(grep "CELL\[" "$stats_file" | grep -v "CELL\[0\]" | wc -l)
    if [ "$num_cells" -eq 0 ]; then
        echo -e "  ${RED}WARNING: Only Cell 0 exists - cpusets not honored!${NC}"
    else
        echo -e "  ${GREEN}Cells 1+ created for cpusetted containers${NC}"
    fi

    # Cleanup
    for ((i=${#CREATED_CGROUPS[@]}-1; i>=0; i--)); do
        cg="${CREATED_CGROUPS[$i]}"
        if [ -d "$cg" ]; then
            cat "$cg/cgroup.procs" 2>/dev/null | while read pid; do
                echo "$pid" > "$CGROUP_ROOT/cgroup.procs" 2>/dev/null || true
            done
            rmdir "$cg" 2>/dev/null || true
        fi
    done
    CREATED_CGROUPS=()

    echo "$post_viol"
    echo "$num_cells"
    echo "$move_detected"
}

if [ ! -f "./target/release/scx_mitosis" ]; then
    echo -e "${RED}scx_mitosis not found${NC}"
    exit 1
fi

echo -e "${YELLOW}=====================================================${NC}"
echo -e "${YELLOW}TEST 1: Cell Creation (cpusetted containers)${NC}"
echo -e "${YELLOW}=====================================================${NC}"
echo "4 containers with cpusets, workloads started before mitosis"
echo ""

result_off=$(run_test "OFF" 2>&1 | tee /dev/stderr | tail -2)
viol_off=$(echo "$result_off" | head -1)
cells_off=$(echo "$result_off" | tail -1)
sleep 2
result_on=$(run_test "ON" 2>&1 | tee /dev/stderr | tail -2)
viol_on=$(echo "$result_on" | head -1)
cells_on=$(echo "$result_on" | tail -1)

echo -e "\n${YELLOW}TEST 1 SUMMARY${NC}"
echo "CPU controller OFF: violations=${viol_off}%, cells_created=${cells_off}"
echo "CPU controller ON:  violations=${viol_on}%, cells_created=${cells_on}"

test1_pass=0
off_zero=$(echo "$viol_off < 1.0" | bc -l 2>/dev/null || echo "0")
on_zero=$(echo "$viol_on < 1.0" | bc -l 2>/dev/null || echo "0")
# Check cells were created for cpusetted containers (should be >0 for both)
off_cells_ok=$([ "$cells_off" -gt 0 ] 2>/dev/null && echo "1" || echo "0")
on_cells_ok=$([ "$cells_on" -gt 0 ] 2>/dev/null && echo "1" || echo "0")

if [ "$off_zero" = "1" ] && [ "$on_zero" = "1" ] && [ "$off_cells_ok" = "1" ] && [ "$on_cells_ok" = "1" ]; then
    echo -e "${GREEN}TEST 1 PASS: No violations and cells created in both cases${NC}"
    test1_pass=1
elif [ "$off_cells_ok" = "0" ]; then
    echo -e "${RED}TEST 1 FAIL: CPU ctrl OFF - no cells created for cpusetted containers${NC}"
else
    echo -e "${RED}TEST 1 FAIL: Violations detected or cells not created${NC}"
fi

echo -e "\n${YELLOW}=====================================================${NC}"
echo -e "${YELLOW}TEST 2: Cgroup Move Detection${NC}"
echo -e "${YELLOW}=====================================================${NC}"
echo "Move workloads between cpusetted containers while mitosis running"
echo ""

sleep 2
move_result_off=$(run_move_test "OFF" 2>&1 | tee /dev/stderr | tail -3)
move_viol_off=$(echo "$move_result_off" | head -1)
move_cells_off=$(echo "$move_result_off" | sed -n '2p')
move_detected_off=$(echo "$move_result_off" | tail -1)
sleep 2
move_result_on=$(run_move_test "ON" 2>&1 | tee /dev/stderr | tail -3)
move_viol_on=$(echo "$move_result_on" | head -1)
move_cells_on=$(echo "$move_result_on" | sed -n '2p')
move_detected_on=$(echo "$move_result_on" | tail -1)

echo -e "\n${YELLOW}TEST 2 SUMMARY${NC}"
echo "CPU controller OFF: violations=${move_viol_off}%, cells=${move_cells_off}, move_detected=${move_detected_off}"
echo "CPU controller ON:  violations=${move_viol_on}%, cells=${move_cells_on}, move_detected=${move_detected_on}"

test2_pass=0
move_off_zero=$(echo "$move_viol_off < 1.0" | bc -l 2>/dev/null || echo "0")
move_on_zero=$(echo "$move_viol_on < 1.0" | bc -l 2>/dev/null || echo "0")
move_off_cells_ok=$([ "$move_cells_off" -gt 0 ] 2>/dev/null && echo "1" || echo "0")
move_on_cells_ok=$([ "$move_cells_on" -gt 0 ] 2>/dev/null && echo "1" || echo "0")

if [ "$move_off_zero" = "1" ] && [ "$move_on_zero" = "1" ] && \
   [ "$move_off_cells_ok" = "1" ] && [ "$move_on_cells_ok" = "1" ] && \
   [ "$move_detected_off" = "1" ] && [ "$move_detected_on" = "1" ]; then
    echo -e "${GREEN}TEST 2 PASS: No violations, cells created, and move detected in both cases${NC}"
    test2_pass=1
elif [ "$move_off_cells_ok" = "0" ]; then
    echo -e "${RED}TEST 2 FAIL: CPU ctrl OFF - no cells created for cpusetted containers${NC}"
elif [ "$move_detected_off" = "0" ]; then
    echo -e "${RED}TEST 2 FAIL: CPU ctrl OFF - move NOT detected (tasks didn't switch cells)${NC}"
else
    echo -e "${RED}TEST 2 FAIL: Violations after move, cells not created, or move not detected${NC}"
fi

echo -e "\n${YELLOW}=====================================================${NC}"
echo -e "${YELLOW}FINAL SUMMARY${NC}"
echo -e "${YELLOW}=====================================================${NC}"
echo "Test 1 (Cell Creation):    $([ "$test1_pass" = "1" ] && echo "PASS" || echo "FAIL")"
echo "Test 2 (Cgroup Move):      $([ "$test2_pass" = "1" ] && echo "PASS" || echo "FAIL")"

if [ "$test1_pass" = "1" ] && [ "$test2_pass" = "1" ]; then
    echo -e "\n${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "\n${RED}SOME TESTS FAILED${NC}"
    exit 1
fi
