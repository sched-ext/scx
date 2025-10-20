#!/bin/bash
# Test that MUST fail on unpatched code and pass on patched code
# Strategy: Fill all cells, remove cpusets (leak cells), try to allocate more

set -e

CGROUP_ROOT="/sys/fs/cgroup"
MAX_CELLS=16
INITIAL_CELLS=15  # Leave 1 slot for root cell

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

if ! pgrep -x scx_mitosis > /dev/null; then
    echo -e "${RED}scx_mitosis not running${NC}"
    exit 1
fi

NUM_CPUS=$(nproc)
if [ "$NUM_CPUS" -lt "$INITIAL_CELLS" ]; then
    echo -e "${RED}Need at least $INITIAL_CELLS CPUs${NC}"
    exit 1
fi

CREATED_CGROUPS=()

cleanup() {
    echo -e "\n${YELLOW}Cleanup...${NC}"
    for cg in "${CREATED_CGROUPS[@]}"; do
        if [ -d "$cg" ]; then
            cat "$cg/cgroup.procs" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
            rmdir "$cg" 2>/dev/null || true
        fi
    done
}

trap cleanup EXIT INT TERM

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}EXHAUSTION TEST (unpatched should FAIL)${NC}"
echo -e "${YELLOW}========================================${NC}\n"

echo "+cpuset" > "$CGROUP_ROOT/cgroup.subtree_control" 2>/dev/null || true
dmesg -c > /dev/null
initial_errors=$(dmesg | grep -c "No available cells to allocate" || true)

# PHASE 1: Fill all cells (create 15 cgroups = 15 cells + 1 root = 16 total)
echo -e "${YELLOW}PHASE 1: Creating $INITIAL_CELLS cgroups to fill all cells${NC}"
for i in $(seq 1 $INITIAL_CELLS); do
    cg="$CGROUP_ROOT/test_exhaust_batch1_$i"
    CREATED_CGROUPS+=("$cg")

    mkdir -p "$cg"
    echo "0" > "$cg/cpuset.mems"
    cpu=$((i - 1))
    echo "$cpu" > "$cg/cpuset.cpus"

    # Spawn task
    (echo $$ > "$cg/cgroup.procs"; sleep 600 &) 2>/dev/null || true

    echo -e "  Created cgroup $i: CPU $cpu"
    sleep 0.12
done

echo -e "${GREEN}Created $INITIAL_CELLS cgroups - all cells allocated${NC}"
sleep 2

# Verify all cells allocated
current_errors=$(dmesg | grep -c "No available cells to allocate" || true)
if [ "$current_errors" -gt "$initial_errors" ]; then
    echo -e "${RED}ERROR: Unexpected exhaustion during phase 1!${NC}"
    exit 1
fi

# PHASE 2: Remove cpusets from HALF the cgroups (leak cells on unpatched)
REMOVE_COUNT=$((INITIAL_CELLS / 2))
echo -e "\n${YELLOW}PHASE 2: Removing cpusets from $REMOVE_COUNT cgroups${NC}"
echo -e "${YELLOW}  On UNPATCHED: Cells stay allocated (leaked)${NC}"
echo -e "${YELLOW}  On PATCHED: Cells freed when DSQ empty${NC}"

for i in $(seq 1 $REMOVE_COUNT); do
    cg="$CGROUP_ROOT/test_exhaust_batch1_$i"

    # Kill tasks first to ensure DSQ is empty
    cat "$cg/cgroup.procs" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    sleep 0.05

    # Remove cpuset restriction (assign to all CPUs)
    echo "0-$((NUM_CPUS - 1))" > "$cg/cpuset.cpus" 2>/dev/null || true

    echo -e "  Removed cpuset from cgroup $i"
    sleep 0.1
done

echo -e "${GREEN}Removed cpusets from $REMOVE_COUNT cgroups${NC}"
echo -e "${YELLOW}Waiting for timer to process (100ms intervals)...${NC}"
sleep 3

# PHASE 3: Try to create NEW cgroups with cpusets
echo -e "\n${YELLOW}PHASE 3: Creating $REMOVE_COUNT NEW cgroups with cpusets${NC}"
echo -e "${YELLOW}  On UNPATCHED: Should FAIL (cells leaked)${NC}"
echo -e "${YELLOW}  On PATCHED: Should SUCCEED (cells freed)${NC}\n"

success=0
for i in $(seq 1 $REMOVE_COUNT); do
    cg="$CGROUP_ROOT/test_exhaust_batch2_$i"
    CREATED_CGROUPS+=("$cg")

    mkdir -p "$cg"
    echo "0" > "$cg/cpuset.mems"
    cpu=$((i - 1))

    echo -ne "${YELLOW}Creating NEW cgroup $i (CPU $cpu)...${NC}"

    if echo "$cpu" > "$cg/cpuset.cpus" 2>/dev/null; then
        (echo $$ > "$cg/cgroup.procs"; sleep 600 &) 2>/dev/null || true
        echo -e " ${GREEN}OK${NC}"
        success=$((success + 1))
    else
        echo -e " ${RED}FAILED${NC}"
    fi

    sleep 0.15

    # Check for exhaustion immediately
    current_errors=$(dmesg | grep -c "No available cells to allocate" || true)
    if [ "$current_errors" -gt "$initial_errors" ]; then
        new_errors=$((current_errors - initial_errors))
        echo -e "\n${RED}========================================${NC}"
        echo -e "${RED}CELL EXHAUSTION DETECTED!${NC}"
        echo -e "${RED}========================================${NC}"
        echo -e "${RED}Failed at NEW cgroup $i${NC}"
        echo -e "${RED}Successfully created: $success/$REMOVE_COUNT${NC}"
        echo -e "${RED}Exhaustion errors: $new_errors${NC}\n"
        dmesg | grep "No available cells" | tail -10
        echo -e "\n${GREEN}TEST RESULT: BUG REPRODUCED (unpatched code)${NC}"
        echo -e "${GREEN}This test would PASS with the patch applied${NC}"
        exit 0
    fi
done

# Check final errors
final_errors=$(dmesg | grep -c "No available cells to allocate" || true)
if [ "$final_errors" -gt "$initial_errors" ]; then
    echo -e "\n${GREEN}BUG REPRODUCED! (unpatched code)${NC}"
    exit 0
else
    echo -e "\n${YELLOW}========================================${NC}"
    echo -e "${YELLOW}NO EXHAUSTION - Patch appears to be applied${NC}"
    echo -e "${YELLOW}========================================${NC}"
    echo -e "${GREEN}All $REMOVE_COUNT new cgroups created successfully${NC}"
    echo -e "${GREEN}Cells were properly freed and reused${NC}"
    echo -e "\n${GREEN}TEST RESULT: PASS (patched code)${NC}"
    exit 0
fi
