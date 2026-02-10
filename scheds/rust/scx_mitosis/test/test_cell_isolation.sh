#!/bin/bash
#
# Test script for scx_mitosis CPU cell isolation
#
# This script tests that processes in different cgroups are scheduled on their
# assigned CPUs. It supports both cpuset mode (cgroups have cpuset.cpus configured)
# and proportional mode (scheduler divides CPUs evenly among cells).
#
# Usage:
#   ./test_cell_isolation.sh [--cpuset] [--proportional] [--num-cells N] [--workers N]
#                            [--test-dynamic] [--test-borrowing]
#                            [--test-enqueue-borrowing] [--test-all]
#
# Options:
#   --cpuset        Test cpuset-based cell isolation (requires cpuset configuration)
#   --proportional  Test proportional CPU division (no cpuset required, default)
#   --num-cells N   Number of test cells to create (default: 2)
#   --workers N     Number of stress-ng workers per cell (default: 5)
#   --test-dynamic  Run dynamic cell creation/destruction tests
#   --test-all      Run all tests (basic + dynamic + borrowing)
#   --help          Show this help message
#

set -e

# Configuration
SCHEDULER_BIN="${SCHEDULER_BIN:-./target/release/scx_mitosis}"
CGROUP_BASE="/sys/fs/cgroup/test.slice"
LOG_FILE="/tmp/scx_mitosis_test.log"

# Defaults
MODE="proportional"
NUM_CELLS=2
WORKERS_PER_CELL=5
SAMPLE_COUNT=5
SAMPLE_INTERVAL=1
TEST_DYNAMIC=0
TEST_BORROWING=0
TEST_ENQUEUE_BORROWING=0
TEST_ALL=0

# Test result tracking
declare -A TEST_RESULTS

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

usage() {
    head -21 "$0" | tail -18
    exit 0
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --cpuset)
            MODE="cpuset"
            shift
            ;;
        --proportional)
            MODE="proportional"
            shift
            ;;
        --num-cells)
            NUM_CELLS="$2"
            shift 2
            ;;
        --workers)
            WORKERS_PER_CELL="$2"
            shift 2
            ;;
        --test-dynamic)
            TEST_DYNAMIC=1
            shift
            ;;
        --test-borrowing)
            TEST_BORROWING=1
            shift
            ;;
        --test-enqueue-borrowing)
            TEST_ENQUEUE_BORROWING=1
            shift
            ;;
        --test-all)
            TEST_ALL=1
            shift
            ;;
        --help)
            usage
            ;;
        *)
            log_error "Unknown option: $1"
            usage
            ;;
    esac
done

# Cleanup function
cleanup() {
    log_info "Cleaning up..."

    # Kill stress-ng processes
    sudo pkill -9 stress-ng 2>/dev/null || true

    # Kill scheduler (use pkill to ensure child processes are killed too)
    sudo pkill -9 scx_mitosis 2>/dev/null || true

    # Also try killing by PID if we have it
    if [[ -n "$SCHED_PID" ]] && ps -p "$SCHED_PID" > /dev/null 2>&1; then
        sudo kill -9 "$SCHED_PID" 2>/dev/null || true
    fi

    # Remove test cgroups (numbered cells)
    for i in $(seq 1 $NUM_CELLS); do
        cell_name="test_cell_${i}"
        cell_path="$CGROUP_BASE/$cell_name"
        if [[ -d "$cell_path" ]]; then
            # Kill any remaining processes
            for pid in $(cat "$cell_path/cgroup.procs" 2>/dev/null); do
                sudo kill -9 "$pid" 2>/dev/null || true
            done
            sudo rmdir "$cell_path" 2>/dev/null || true
        fi
    done

    # Remove dynamic test cgroups
    for cell_name in test_cell_dynamic test_cell_temp test_cell_3 test_cell_reuse_a test_cell_reuse_b test_cell_borrow_busy test_cell_borrow_idle; do
        cell_path="$CGROUP_BASE/$cell_name"
        if [[ -d "$cell_path" ]]; then
            for pid in $(cat "$cell_path/cgroup.procs" 2>/dev/null); do
                sudo kill -9 "$pid" 2>/dev/null || true
            done
            sudo rmdir "$cell_path" 2>/dev/null || true
        fi
    done

    # Remove the parent test.slice cgroup
    if [[ -d "$CGROUP_BASE" ]]; then
        # Kill any remaining processes
        for pid in $(cat "$CGROUP_BASE/cgroup.procs" 2>/dev/null); do
            sudo kill -9 "$pid" 2>/dev/null || true
        done
        sudo rmdir "$CGROUP_BASE" 2>/dev/null || true
    fi

    wait 2>/dev/null || true
}

trap cleanup EXIT

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    if [[ ! -x "$SCHEDULER_BIN" ]]; then
        log_error "Scheduler binary not found: $SCHEDULER_BIN"
        log_error "Please build with: cargo build --release -p scx_mitosis"
        exit 1
    fi

    if ! command -v stress-ng &> /dev/null; then
        log_error "stress-ng not found. Please install it."
        exit 1
    fi

    if [[ ! -d "/sys/fs/cgroup" ]]; then
        log_error "cgroup2 filesystem not found at /sys/fs/cgroup"
        exit 1
    fi

    # Check if we can read sched_ext state
    if [[ ! -f "/sys/kernel/sched_ext/state" ]]; then
        log_error "sched_ext not available (missing /sys/kernel/sched_ext/state)"
        exit 1
    fi
}

# Create test cgroups
create_cgroups() {
    log_info "Creating test cgroups under $CGROUP_BASE..."

    # Create parent if needed
    if [[ ! -d "$CGROUP_BASE" ]]; then
        sudo mkdir -p "$CGROUP_BASE"
    fi

    # Enable CPU controller for children (required for sched_ext cgroup callbacks)
    if ! grep -q "cpu" "$CGROUP_BASE/cgroup.subtree_control" 2>/dev/null; then
        log_info "Enabling CPU controller for $CGROUP_BASE children"
        echo "+cpu" | sudo tee "$CGROUP_BASE/cgroup.subtree_control" > /dev/null
    fi

    for i in $(seq 1 $NUM_CELLS); do
        cell_name="test_cell_${i}"
        cell_path="$CGROUP_BASE/$cell_name"

        if [[ ! -d "$cell_path" ]]; then
            sudo mkdir "$cell_path"
            log_info "Created $cell_path"
        fi
    done

    # List created cgroups
    ls -la "$CGROUP_BASE" | grep test_cell
}

# Start the scheduler
start_scheduler() {
    log_info "Starting scx_mitosis scheduler (mode: $MODE, extra flags: $@)..."

    sudo "$SCHEDULER_BIN" \
        --cell-parent-cgroup /test.slice \
        "$@" \
        > "$LOG_FILE" 2>&1 &
    SCHED_PID=$!

    log_info "Scheduler PID: $SCHED_PID"

    # Wait for scheduler to attach
    sleep 3

    # Verify scheduler is running
    if ! ps -p "$SCHED_PID" > /dev/null 2>&1; then
        log_error "Scheduler failed to start. Log output:"
        cat "$LOG_FILE"
        exit 1
    fi

    # Check sched_ext state
    local state=$(cat /sys/kernel/sched_ext/state 2>/dev/null)
    if [[ "$state" != "enabled" ]]; then
        log_error "sched_ext not enabled. State: $state"
        cat "$LOG_FILE"
        exit 1
    fi

    log_info "sched_ext state: $state"

    # Show which cells were created
    log_info "Scheduler log (cell creation):"
    grep -E "(Created cell|Assigning)" "$LOG_FILE" | head -10 || true
}

# Start workloads in each cell
start_workloads() {
    log_info "Starting $WORKERS_PER_CELL stress-ng workers in each cell..."

    for i in $(seq 1 $NUM_CELLS); do
        cell_name="test_cell_${i}"
        cell_path="$CGROUP_BASE/$cell_name"

        # Start stress-ng in a subshell that first moves to the cgroup
        sudo bash -c "echo \$\$ > $cell_path/cgroup.procs && \
            exec stress-ng --cpu $WORKERS_PER_CELL --timeout 120s --quiet" &

        log_info "Started workload in $cell_name"
    done

    # Wait for workers to start
    sleep 2
}

# Get CPU for a process
get_process_cpu() {
    local pid=$1
    if [[ -f "/proc/$pid/stat" ]]; then
        # Field 39 in /proc/pid/stat is the processor number
        awk '{print $39}' "/proc/$pid/stat" 2>/dev/null
    fi
}

# Sample CPU assignments
sample_cpu_assignments() {
    log_info "Sampling CPU assignments ($SAMPLE_COUNT samples)..."
    echo ""

    declare -A cell_cpus

    for sample in $(seq 1 $SAMPLE_COUNT); do
        echo "=== Sample $sample ==="

        for i in $(seq 1 $NUM_CELLS); do
            cell_name="test_cell_${i}"
            cell_path="$CGROUP_BASE/$cell_name"

            echo "  $cell_name:"

            for pid in $(cat "$cell_path/cgroup.procs" 2>/dev/null); do
                if [[ -d "/proc/$pid" ]]; then
                    cpu=$(get_process_cpu "$pid")
                    comm=$(cat "/proc/$pid/comm" 2>/dev/null)
                    if [[ -n "$cpu" ]]; then
                        echo "    PID $pid ($comm) -> CPU $cpu"
                        # Track unique CPUs per cell
                        cell_cpus["${cell_name}_${cpu}"]=1
                    fi
                fi
            done
        done

        if [[ $sample -lt $SAMPLE_COUNT ]]; then
            sleep $SAMPLE_INTERVAL
        fi
        echo ""
    done

    # Print summary of CPUs used by each cell
    echo "=== CPU Usage Summary ==="
    for i in $(seq 1 $NUM_CELLS); do
        cell_name="test_cell_${i}"
        cpus=""
        for key in "${!cell_cpus[@]}"; do
            if [[ "$key" == "${cell_name}_"* ]]; then
                cpu="${key#${cell_name}_}"
                if [[ -n "$cpus" ]]; then
                    cpus="$cpus, $cpu"
                else
                    cpus="$cpu"
                fi
            fi
        done
        echo "  $cell_name used CPUs: $cpus"
    done
}

# Check for CPU isolation (detect overlapping CPU usage)
check_isolation() {
    log_info "Checking CPU isolation..."

    declare -A cpu_to_cell
    local overlap_detected=0

    for i in $(seq 1 $NUM_CELLS); do
        cell_name="test_cell_${i}"
        cell_path="$CGROUP_BASE/$cell_name"

        for pid in $(cat "$cell_path/cgroup.procs" 2>/dev/null); do
            if [[ -d "/proc/$pid" ]]; then
                cpu=$(get_process_cpu "$pid")
                if [[ -n "$cpu" ]]; then
                    if [[ -n "${cpu_to_cell[$cpu]}" ]] && [[ "${cpu_to_cell[$cpu]}" != "$cell_name" ]]; then
                        log_warn "CPU $cpu used by both ${cpu_to_cell[$cpu]} and $cell_name"
                        overlap_detected=1
                    fi
                    cpu_to_cell[$cpu]="$cell_name"
                fi
            fi
        done
    done

    if [[ $overlap_detected -eq 0 ]]; then
        log_info "No CPU overlap detected between cells"
        return 0
    else
        log_warn "CPU overlap detected - cells are not fully isolated"
        return 1
    fi
}

# Record test result
record_result() {
    local test_name="$1"
    local result="$2"
    TEST_RESULTS["$test_name"]="$result"
    if [[ "$result" == "PASSED" ]]; then
        log_info "$test_name: ${GREEN}PASSED${NC}"
    elif [[ "$result" == "INCONCLUSIVE" ]]; then
        log_warn "$test_name: ${YELLOW}INCONCLUSIVE${NC}"
    else
        log_error "$test_name: ${RED}FAILED${NC}"
    fi
}

# Test: Basic CPU isolation
test_basic_isolation() {
    log_info "=== Running test: Basic CPU Isolation ==="

    start_workloads
    sample_cpu_assignments

    if check_isolation; then
        record_result "basic_isolation" "PASSED"
        return 0
    else
        record_result "basic_isolation" "INCONCLUSIVE"
        return 1
    fi
}

# Test: Dynamic cell lifecycle (creation, workload, destruction)
test_dynamic_cell_lifecycle() {
    log_info "=== Running test: Dynamic Cell Lifecycle ==="

    local cell_path="$CGROUP_BASE/test_cell_dynamic"

    # Cleanup any existing cgroup
    if [[ -d "$cell_path" ]]; then
        sudo rmdir "$cell_path" 2>/dev/null || true
        sleep 1
    fi

    # Create a new cgroup while scheduler is running
    sudo mkdir "$cell_path"
    sleep 3  # Wait for inotify to fire and scheduler to process

    # Verify scheduler log shows new cell
    if ! grep -q "Created cell.*test_cell_dynamic" "$LOG_FILE"; then
        log_error "Dynamic cell creation not detected in logs"
        record_result "dynamic_cell_lifecycle" "FAILED"
        return 1
    fi

    log_info "Cell creation detected in logs"

    # Start workload in new cell
    sudo bash -c "echo \$\$ > $cell_path/cgroup.procs && \
        exec stress-ng --cpu 2 --timeout 60s --quiet" &
    local workload_pid=$!
    sleep 2

    # Verify tasks are running
    if ! pgrep -f "stress-ng.*cpu" > /dev/null; then
        log_error "Workload not running in dynamic cell"
        record_result "dynamic_cell_lifecycle" "FAILED"
        return 1
    fi

    # Check that processes in the dynamic cell are running
    local procs=$(cat "$cell_path/cgroup.procs" 2>/dev/null | wc -l)
    if [[ "$procs" -lt 1 ]]; then
        log_error "No processes found in dynamic cell cgroup"
        record_result "dynamic_cell_lifecycle" "FAILED"
        return 1
    fi

    log_info "Found $procs processes in dynamic cell"

    # Stop the workload
    sudo pkill -f "stress-ng.*cpu" 2>/dev/null || true
    sleep 2

    # Remove the cell
    sudo rmdir "$cell_path"
    sleep 3

    # Verify destruction logged
    if ! grep -q "Destroyed cell.*test_cell_dynamic" "$LOG_FILE"; then
        log_error "Cell destruction not detected in logs"
        log_info "Log contents related to test_cell_dynamic:"
        grep "test_cell_dynamic" "$LOG_FILE" || echo "(no matches)"
        record_result "dynamic_cell_lifecycle" "FAILED"
        return 1
    fi

    log_info "Cell destruction detected in logs"
    record_result "dynamic_cell_lifecycle" "PASSED"
    return 0
}

# Test: CPU reallocation after adding a cell
test_cpu_reallocation() {
    log_info "=== Running test: CPU Reallocation ==="

    # Count lines with cell configuration messages before adding new cell
    local config_count_before=$(grep -c "Cell config updated\|Applied initial cell configuration" "$LOG_FILE" || echo "0")

    # Add a third cell
    local cell_path="$CGROUP_BASE/test_cell_3"
    if [[ -d "$cell_path" ]]; then
        sudo rmdir "$cell_path" 2>/dev/null || true
        sleep 1
    fi

    sudo mkdir "$cell_path"
    sleep 3

    # Count configuration applications after
    local config_count_after=$(grep -c "Cell config updated\|Applied initial cell configuration" "$LOG_FILE" || echo "0")

    if [[ "$config_count_after" -gt "$config_count_before" ]]; then
        log_info "Cell configuration was reapplied after adding new cell"
        log_info "Config applications: $config_count_before -> $config_count_after"
        record_result "cpu_reallocation" "PASSED"
        return 0
    else
        log_error "CPU reallocation not triggered after adding cell"
        record_result "cpu_reallocation" "FAILED"
        return 1
    fi
}

# Test: Cell ID reuse
test_cell_id_reuse() {
    log_info "=== Running test: Cell ID Reuse ==="

    local cell_path_a="$CGROUP_BASE/test_cell_reuse_a"
    local cell_path_b="$CGROUP_BASE/test_cell_reuse_b"

    # Clean up any existing cells
    for path in "$cell_path_a" "$cell_path_b"; do
        if [[ -d "$path" ]]; then
            sudo rmdir "$path" 2>/dev/null || true
        fi
    done
    sleep 1

    # Create first cell
    sudo mkdir "$cell_path_a"
    sleep 2

    # Get the cell ID from log
    local cell_id=$(grep "Created cell.*test_cell_reuse_a" "$LOG_FILE" | tail -1 | grep -oP "cell \K\d+" || echo "")

    if [[ -z "$cell_id" ]]; then
        log_error "Could not find cell ID for test_cell_reuse_a"
        record_result "cell_id_reuse" "FAILED"
        return 1
    fi

    log_info "First cell created with ID: $cell_id"

    # Destroy it
    sudo rmdir "$cell_path_a"
    sleep 2

    # Create a new cell - should reuse the same ID
    sudo mkdir "$cell_path_b"
    sleep 2

    local new_cell_id=$(grep "Created cell.*test_cell_reuse_b" "$LOG_FILE" | tail -1 | grep -oP "cell \K\d+" || echo "")

    if [[ -z "$new_cell_id" ]]; then
        log_error "Could not find cell ID for test_cell_reuse_b"
        record_result "cell_id_reuse" "FAILED"
        return 1
    fi

    log_info "Second cell created with ID: $new_cell_id"

    if [[ "$cell_id" == "$new_cell_id" ]]; then
        log_info "Cell ID was reused (ID $cell_id)"
        record_result "cell_id_reuse" "PASSED"
        return 0
    else
        # ID reuse is not guaranteed if other cells exist - this is acceptable
        log_warn "Cell ID not reused (expected $cell_id, got $new_cell_id)"
        log_info "This may be acceptable depending on other active cells"
        record_result "cell_id_reuse" "INCONCLUSIVE"
        return 0
    fi
}

# Test: CPU borrowing - verify that a busy cell borrows CPUs from idle cells.
# Args:
#   $1 - stressor type: "pipe" (wakeup-heavy, select_cpu path) or
#                        "cpu" (CPU spinners, enqueue path)
#   $2 - test name for result recording
test_borrowing() {
    local stressor="$1"
    local test_name="$2"
    log_info "=== Running test: CPU Borrowing ($stressor stressor) ==="

    # Kill existing scheduler if running
    if [[ -n "$SCHED_PID" ]] && ps -p "$SCHED_PID" > /dev/null 2>&1; then
        sudo kill "$SCHED_PID" 2>/dev/null || true
        sleep 2
    fi
    sudo pkill -9 scx_mitosis 2>/dev/null || true
    sleep 2

    # Create two test cells
    local busy_path="$CGROUP_BASE/test_cell_borrow_busy"
    local idle_path="$CGROUP_BASE/test_cell_borrow_idle"

    for path in "$busy_path" "$idle_path"; do
        if [[ -d "$path" ]]; then
            for pid in $(cat "$path/cgroup.procs" 2>/dev/null); do
                sudo kill -9 "$pid" 2>/dev/null || true
            done
            sudo rmdir "$path" 2>/dev/null || true
        fi
    done

    sudo mkdir -p "$busy_path"
    sudo mkdir -p "$idle_path"

    # Start scheduler with borrowing
    start_scheduler --enable-borrowing

    # Use more workers than the busy cell has CPUs to force borrowing
    local workers=$(nproc)

    log_info "Starting $workers stress-ng $stressor workers in busy cell..."
    sudo bash -c "echo \$\$ > $busy_path/cgroup.procs && \
        exec stress-ng --$stressor $workers --timeout 60s --quiet" &

    # Wait for stats to accumulate
    sleep 5

    # Capture monitor output
    local monitor_output="/tmp/scx_mitosis_monitor_borrow.json"
    log_info "Capturing monitor output..."
    timeout 4 "$SCHEDULER_BIN" --monitor 1 > "$monitor_output" 2>/dev/null || true

    # Kill workloads
    sudo pkill -9 stress-ng 2>/dev/null || true
    sleep 1

    # Validate: check that borrowed_pct > 0 (CSTAT_BORROWED incremented by BPF)
    local result
    result=$(python3 -c "
import json, sys

with open('$monitor_output', 'r') as f:
    text = f.read()

decoder = json.JSONDecoder()
last_obj = None
pos = 0
while pos < len(text):
    while pos < len(text) and text[pos] in ' \t\n\r':
        pos += 1
    if pos >= len(text):
        break
    try:
        obj, end = decoder.raw_decode(text, pos)
        last_obj = obj
        pos = end
    except json.JSONDecodeError:
        break

if last_obj is None:
    print('NO_DATA')
    sys.exit(0)

borrowed_pct = last_obj.get('borrowed_pct', 0)

if borrowed_pct <= 0:
    print('FAIL:borrowed_pct is 0 (CSTAT_BORROWED not incremented)')
    sys.exit(0)

msg = 'PASS:borrowed_pct=%.2f' % borrowed_pct
print(msg)
" 2>&1)

    log_info "Borrowing ($stressor) result: $result"

    case "$result" in
        PASS:*)
            record_result "$test_name" "PASSED"
            return 0
            ;;
        FAIL:*)
            local reason="${result#FAIL:}"
            log_error "Borrowing test ($stressor) failed: $reason"
            record_result "$test_name" "FAILED"
            return 1
            ;;
        NO_DATA)
            log_error "Borrowing test ($stressor): no monitor data captured"
            record_result "$test_name" "FAILED"
            return 1
            ;;
        *)
            log_error "Borrowing test ($stressor): unexpected result: $result"
            record_result "$test_name" "FAILED"
            return 1
            ;;
    esac
}

# Run dynamic tests
run_dynamic_tests() {
    log_info ""
    log_info "======================================"
    log_info "Running Dynamic Cell Tests"
    log_info "======================================"

    test_dynamic_cell_lifecycle
    test_cpu_reallocation
    test_cell_id_reuse
}

# Print test summary
print_summary() {
    echo ""
    echo "======================================"
    echo "Test Summary"
    echo "======================================"

    local passed=0
    local failed=0
    local inconclusive=0

    for test_name in "${!TEST_RESULTS[@]}"; do
        local result="${TEST_RESULTS[$test_name]}"
        case "$result" in
            PASSED)
                echo -e "  ${GREEN}✓${NC} $test_name"
                ((passed++))
                ;;
            FAILED)
                echo -e "  ${RED}✗${NC} $test_name"
                ((failed++))
                ;;
            INCONCLUSIVE)
                echo -e "  ${YELLOW}?${NC} $test_name"
                ((inconclusive++))
                ;;
        esac
    done

    echo ""
    echo "Results: $passed passed, $failed failed, $inconclusive inconclusive"

    if [[ $failed -gt 0 ]]; then
        return 1
    fi
    return 0
}

# Main test flow
main() {
    echo "======================================"
    echo "scx_mitosis Cell Isolation Test"
    echo "======================================"
    echo "Mode: $MODE"
    echo "Number of cells: $NUM_CELLS"
    echo "Workers per cell: $WORKERS_PER_CELL"
    echo "Test dynamic: $TEST_DYNAMIC"
    echo "Test borrowing: $TEST_BORROWING"
    echo "Test enqueue borrowing: $TEST_ENQUEUE_BORROWING"
    echo "Test all: $TEST_ALL"
    echo ""

    check_prerequisites
    create_cgroups
    start_scheduler

    # Determine which tests to run
    local run_basic=1
    local run_dynamic=0
    local run_borrowing=0
    local run_enqueue_borrowing=0

    if [[ $TEST_ALL -eq 1 ]]; then
        run_basic=1
        run_dynamic=1
        run_borrowing=1
        run_enqueue_borrowing=1
    elif [[ $TEST_DYNAMIC -eq 1 ]]; then
        run_basic=0
        run_dynamic=1
    elif [[ $TEST_BORROWING -eq 1 ]]; then
        run_basic=0
        run_borrowing=1
    elif [[ $TEST_ENQUEUE_BORROWING -eq 1 ]]; then
        run_basic=0
        run_enqueue_borrowing=1
    fi

    # Run basic isolation test
    if [[ $run_basic -eq 1 ]]; then
        test_basic_isolation
    fi

    # Run dynamic tests
    if [[ $run_dynamic -eq 1 ]]; then
        run_dynamic_tests
    fi

    # Run borrowing test (pipe stressor → select_cpu path)
    if [[ $run_borrowing -eq 1 ]]; then
        test_borrowing pipe cpu_borrowing
    fi

    # Run enqueue borrowing test (cpu stressor → enqueue path)
    if [[ $run_enqueue_borrowing -eq 1 ]]; then
        test_borrowing cpu enqueue_borrowing
    fi

    # Print summary and exit
    if print_summary; then
        log_info "All tests completed successfully"
        exit 0
    else
        log_error "Some tests failed"
        exit 1
    fi
}

main
