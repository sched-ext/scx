#!/bin/bash
# Comprehensive test for cpuset effective_cpus handling
# Tests: leaf cpusets, mid-path cpusets, nested cpusets

set -e

CGROUP_ROOT="/sys/fs/cgroup"
TEST_DURATION=8

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

NUM_CPUS=$(nproc)
echo "System has $NUM_CPUS CPUs"

STRESS_PIDS=()
CREATED_CGROUPS=()
TEST_RESULTS=()

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

# Disable CPU controller, enable cpuset
echo "-cpu +cpuset" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true

run_test() {
    local test_name=$1
    local expected_cpus=$2
    local log_file="/tmp/mitosis_${test_name}.log"

    echo -e "\n${YELLOW}Starting mitosis...${NC}"
    /home/patso/repos/scx/target/debug/scx_mitosis --log-level trace 2>&1 | tee "$log_file" &
    local mitosis_pid=$!
    sleep 2

    if ! kill -0 $mitosis_pid 2>/dev/null; then
        echo -e "${RED}Mitosis failed to start${NC}"
        wait $mitosis_pid 2>/dev/null || true
        TEST_RESULTS+=("$test_name: FAIL (mitosis crashed)")
        return 1
    fi

    echo -e "${YELLOW}Running for ${TEST_DURATION}s...${NC}"
    sleep $TEST_DURATION

    echo -e "${YELLOW}Stopping mitosis...${NC}"
    kill $mitosis_pid 2>/dev/null || true
    wait $mitosis_pid 2>/dev/null || true
    sleep 1

    # Extract num_cpus from log - look for "Num CPUs:" or cell cpumask info
    echo -e "${YELLOW}Analyzing output...${NC}"

    # Count CPUs from CELL cpumask lines (non-root cells)
    # CELL[N]: shows the cpumask, count set bits for cells > 0
    local total_cell_cpus=0
    local cells_found=0

    # Get unique CELL lines (last occurrence of each cell)
    grep "CELL\[" "$log_file" | while read line; do
        echo "  $line"
    done | tail -20

    # Extract violations
    local violations=$(grep "V:" "$log_file" | tail -5 | grep -oP 'V:\s*\K[0-9.]+' | tail -1)
    echo "  Last violations: ${violations:-N/A}%"

    # Count CPUs in non-root cells from the cpumask
    # Format: CELL[N]: hex,hex
    local cell_cpu_count=0
    for cell_line in $(grep "CELL\[" "$log_file" | grep -v "CELL\[0\]" | tail -10); do
        # Extract the hex cpumask and count bits
        local mask=$(echo "$cell_line" | grep -oP 'CELL\[\d+\]:\s*\K[0-9a-f,]+')
        if [ -n "$mask" ]; then
            # Remove commas and count 1 bits
            local clean_mask=$(echo "$mask" | tr -d ',')
            # Count bits set in hex
            local bits=$(echo "obase=2; ibase=16; ${clean_mask^^}" | bc 2>/dev/null | tr -cd '1' | wc -c)
            cell_cpu_count=$((cell_cpu_count + bits))
        fi
    done

    echo ""
    echo "  Expected CPUs in cells: $expected_cpus"
    echo "  Violations: ${violations:-0}%"

    # Check if test passed
    if [ "${violations:-100}" = "0.0" ] || [ "${violations:-100}" = "0" ]; then
        echo -e "  ${GREEN}PASS: No violations${NC}"
        TEST_RESULTS+=("$test_name: PASS (0% violations)")
    else
        echo -e "  ${RED}FAIL: Violations = ${violations}%${NC}"
        TEST_RESULTS+=("$test_name: FAIL (${violations}% violations)")
    fi
}

cleanup_cgroups() {
    for pid in "${STRESS_PIDS[@]}"; do
        kill -9 "$pid" 2>/dev/null || true
    done
    STRESS_PIDS=()

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
    sleep 1
}

echo -e "\n${YELLOW}======================================${NC}"
echo -e "${YELLOW}TEST 1: Leaf cgroups with cpusets${NC}"
echo -e "${YELLOW}======================================${NC}"
echo "4 leaf containers, each with 4 CPUs (0-3, 4-7, 8-11, 12-15)"
echo "Expected: 16 CPUs total in non-root cells"

for i in 0 1 2 3; do
    cg="$CGROUP_ROOT/leaf$i"
    mkdir -p "$cg"
    CREATED_CGROUPS+=("$cg")
    start=$((i * 4))
    end=$((start + 3))
    echo "$start-$end" > "$cg/cpuset.cpus"
    echo "  leaf$i: cpuset=$start-$end effective=$(cat $cg/cpuset.cpus.effective)"

    stress-ng --cpu 2 --timeout 60s --quiet &
    pid=$!
    STRESS_PIDS+=($pid)
    echo $pid > "$cg/cgroup.procs"
done

run_test "leaf_cpusets" 16
cleanup_cgroups

echo -e "\n${YELLOW}======================================${NC}"
echo -e "${YELLOW}TEST 2: Mid-path cpuset with leaf children${NC}"
echo -e "${YELLOW}======================================${NC}"
echo "1 parent with cpuset 0-15, 4 leaf children (no explicit cpuset)"
echo "Children inherit parent's effective_cpus"
echo "Expected: 16 CPUs (all from parent's cell)"

# Enable cpuset on subtree
echo "+cpuset" > "$CGROUP_ROOT/cgroup.subtree_control"

parent="$CGROUP_ROOT/parent_cpuset"
mkdir -p "$parent"
CREATED_CGROUPS+=("$parent")
echo "0-15" > "$parent/cpuset.cpus"
echo "  parent: cpuset=0-15 effective=$(cat $parent/cpuset.cpus.effective)"

# Enable cpuset propagation to children
echo "+cpuset" > "$parent/cgroup.subtree_control"

for i in 0 1 2 3; do
    cg="$parent/child$i"
    mkdir -p "$cg"
    CREATED_CGROUPS+=("$cg")
    # No cpuset set on children - they inherit from parent
    echo "  child$i: cpuset=$(cat $cg/cpuset.cpus 2>/dev/null || echo 'inherited') effective=$(cat $cg/cpuset.cpus.effective)"

    stress-ng --cpu 2 --timeout 60s --quiet &
    pid=$!
    STRESS_PIDS+=($pid)
    echo $pid > "$cg/cgroup.procs"
done

run_test "midpath_cpuset" 16
cleanup_cgroups

echo -e "\n${YELLOW}======================================${NC}"
echo -e "${YELLOW}TEST 3: Nested cpusets (parent and children)${NC}"
echo -e "${YELLOW}======================================${NC}"
echo "Parent with cpuset 0-15, children with narrower cpusets"
echo "Expected: 16 CPUs (4 cells of 4 CPUs each)"

echo "+cpuset" > "$CGROUP_ROOT/cgroup.subtree_control"

parent="$CGROUP_ROOT/nested_parent"
mkdir -p "$parent"
CREATED_CGROUPS+=("$parent")
echo "0-15" > "$parent/cpuset.cpus"
echo "  parent: cpuset=0-15 effective=$(cat $parent/cpuset.cpus.effective)"

echo "+cpuset" > "$parent/cgroup.subtree_control"

for i in 0 1 2 3; do
    cg="$parent/nested_child$i"
    mkdir -p "$cg"
    CREATED_CGROUPS+=("$cg")
    start=$((i * 4))
    end=$((start + 3))
    echo "$start-$end" > "$cg/cpuset.cpus"
    echo "  nested_child$i: cpuset=$start-$end effective=$(cat $cg/cpuset.cpus.effective)"

    stress-ng --cpu 2 --timeout 60s --quiet &
    pid=$!
    STRESS_PIDS+=($pid)
    echo $pid > "$cg/cgroup.procs"
done

run_test "nested_cpusets" 16
cleanup_cgroups

echo -e "\n${YELLOW}======================================${NC}"
echo -e "${YELLOW}TEST 4: Deep hierarchy (3 levels)${NC}"
echo -e "${YELLOW}======================================${NC}"
echo "grandparent(0-31) -> parent(0-15) -> child(0-7)"
echo "Expected: 8 CPUs in child's cell"

echo "+cpuset" > "$CGROUP_ROOT/cgroup.subtree_control"

gparent="$CGROUP_ROOT/gparent"
mkdir -p "$gparent"
CREATED_CGROUPS+=("$gparent")
echo "0-31" > "$gparent/cpuset.cpus"
echo "+cpuset" > "$gparent/cgroup.subtree_control"
echo "  grandparent: cpuset=0-31 effective=$(cat $gparent/cpuset.cpus.effective)"

parent="$gparent/dparent"
mkdir -p "$parent"
CREATED_CGROUPS+=("$parent")
echo "0-15" > "$parent/cpuset.cpus"
echo "+cpuset" > "$parent/cgroup.subtree_control"
echo "  parent: cpuset=0-15 effective=$(cat $parent/cpuset.cpus.effective)"

child="$parent/dchild"
mkdir -p "$child"
CREATED_CGROUPS+=("$child")
echo "0-7" > "$child/cpuset.cpus"
echo "  child: cpuset=0-7 effective=$(cat $child/cpuset.cpus.effective)"

stress-ng --cpu 4 --timeout 60s --quiet &
pid=$!
STRESS_PIDS+=($pid)
echo $pid > "$child/cgroup.procs"

run_test "deep_hierarchy" 8
cleanup_cgroups

echo -e "\n${YELLOW}======================================${NC}"
echo -e "${YELLOW}TEST 5: Mid-path only (no leaf cpuset)${NC}"
echo -e "${YELLOW}======================================${NC}"
echo "Parent with cpuset 0-7, single child with tasks (no cpuset on child)"
echo "Child inherits parent effective. Expected: 8 CPUs"

echo "+cpuset" > "$CGROUP_ROOT/cgroup.subtree_control"

parent="$CGROUP_ROOT/midonly_parent"
mkdir -p "$parent"
CREATED_CGROUPS+=("$parent")
echo "0-7" > "$parent/cpuset.cpus"
echo "+cpuset" > "$parent/cgroup.subtree_control"
echo "  parent: cpuset=0-7 effective=$(cat $parent/cpuset.cpus.effective)"

child="$parent/midonly_child"
mkdir -p "$child"
CREATED_CGROUPS+=("$child")
# No cpuset on child
echo "  child: cpuset=$(cat $child/cpuset.cpus 2>/dev/null || echo 'inherited') effective=$(cat $child/cpuset.cpus.effective)"

stress-ng --cpu 4 --timeout 60s --quiet &
pid=$!
STRESS_PIDS+=($pid)
echo $pid > "$child/cgroup.procs"

run_test "midpath_only" 8
cleanup_cgroups

echo -e "\n${YELLOW}======================================${NC}"
echo -e "${GREEN}FINAL RESULTS${NC}"
echo -e "${YELLOW}======================================${NC}"

pass_count=0
fail_count=0
for result in "${TEST_RESULTS[@]}"; do
    echo "  $result"
    if [[ "$result" == *"PASS"* ]]; then
        ((pass_count++))
    else
        ((fail_count++))
    fi
done

echo ""
echo "Passed: $pass_count / $((pass_count + fail_count))"

if [ $fail_count -eq 0 ]; then
    echo -e "${GREEN}ALL TESTS PASSED${NC}"
    exit 0
else
    echo -e "${RED}SOME TESTS FAILED${NC}"
    exit 1
fi
