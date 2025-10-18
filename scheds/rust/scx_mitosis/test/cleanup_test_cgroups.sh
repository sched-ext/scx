#!/bin/bash
# Cleanup all test cgroups created by test scripts

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Must run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}========================================${NC}"
echo -e "${YELLOW}Cleaning up all test cgroups${NC}"
echo -e "${YELLOW}========================================${NC}\n"

# Find all test-related cgroups with pattern matching
TEST_PATTERNS=(
    "test_mitosis*"
    "test_cell*"
    "test_simple*"
    "test_brutal*"
    "test_absolute*"
    "test_working*"
    "test_reuse*"
    "test_verify*"
    "test_cycle*"
    "test_16*"
    "test_15*"
    "test_*"
    "scx_mitosis_test*"
)

CLEANED=0
FAILED=0

# First pass: Find all matching cgroups at root level
ALL_TEST_CGROUPS=()
for pattern in "${TEST_PATTERNS[@]}"; do
    shopt -s nullglob  # Make glob return nothing if no matches
    for cg in /sys/fs/cgroup/${pattern}; do
        if [ -d "$cg" ]; then
            ALL_TEST_CGROUPS+=("$cg")
        fi
    done
    shopt -u nullglob
done

# Remove duplicates and sort
UNIQUE_CGROUPS=($(printf '%s\n' "${ALL_TEST_CGROUPS[@]}" | sort -u))

if [ ${#UNIQUE_CGROUPS[@]} -eq 0 ]; then
    echo -e "${GREEN}No test cgroups found to clean up${NC}"
    exit 0
fi

echo -e "${YELLOW}Found ${#UNIQUE_CGROUPS[@]} test cgroups to clean up${NC}\n"

# Clean each cgroup
for test_root in "${UNIQUE_CGROUPS[@]}"; do
    if [ ! -d "$test_root" ]; then
        continue
    fi

    echo -e "${YELLOW}Cleaning $(basename $test_root)...${NC}"

    # Find all child cgroups, deepest first
    if [ -d "$test_root" ]; then
        find "$test_root" -mindepth 1 -type d 2>/dev/null | sort -r | while read -r cg; do
            # Kill all processes in the cgroup
            if [ -f "$cg/cgroup.procs" ]; then
                cat "$cg/cgroup.procs" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
            fi
            sleep 0.05
            # Remove the cgroup
            rmdir "$cg" 2>/dev/null || true
        done
    fi

    # Remove the root test cgroup
    if [ -f "$test_root/cgroup.procs" ]; then
        cat "$test_root/cgroup.procs" 2>/dev/null | xargs -r kill -9 2>/dev/null || true
    fi
    sleep 0.1
    rmdir "$test_root" 2>/dev/null || true

    if [ -d "$test_root" ]; then
        echo -e "${RED}  ✗ Failed to remove $(basename $test_root)${NC}"
        FAILED=$((FAILED + 1))
    else
        echo -e "${GREEN}  ✓ Removed $(basename $test_root)${NC}"
        CLEANED=$((CLEANED + 1))
    fi
done

echo -e "\n${YELLOW}========================================${NC}"
echo -e "${GREEN}Cleaned: $CLEANED cgroups${NC}"
if [ $FAILED -gt 0 ]; then
    echo -e "${RED}Failed: $FAILED cgroups${NC}"
    echo -e "${YELLOW}Try running the cleanup again if some cgroups are still active${NC}"
else
    echo -e "${GREEN}All test cgroups removed successfully!${NC}"
fi
echo -e "${YELLOW}========================================${NC}"
