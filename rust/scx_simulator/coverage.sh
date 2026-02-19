#!/bin/bash
# coverage.sh — C code coverage for scx_simulator scheduler .so files
#
# Builds with clang source-based coverage instrumentation, runs tests,
# merges profile data, and generates reports.
#
# Usage:
#   ./coverage.sh [--html] [--lcov] [--keep-profraw] [--all]
#
# Environment:
#   SCX_SIM_COVERAGE=1 is set automatically by this script.
set -euo pipefail

cd "$(dirname "$0")"
SCRIPT_DIR="$(pwd)"
PROJ_ROOT="$(cd ../.. && pwd)"
COVERAGE_OUT="$SCRIPT_DIR/coverage-out"

# --- Parse flags ---
FLAG_HTML=0
FLAG_LCOV=0
FLAG_KEEP_PROFRAW=0
FLAG_ALL=0
for arg in "$@"; do
    case "$arg" in
        --html)         FLAG_HTML=1 ;;
        --lcov)         FLAG_LCOV=1 ;;
        --keep-profraw) FLAG_KEEP_PROFRAW=1 ;;
        --all)          FLAG_ALL=1 ;;
        -h|--help)
            echo "Usage: $0 [--html] [--lcov] [--keep-profraw] [--all]"
            echo ""
            echo "  --html          Generate HTML coverage report"
            echo "  --lcov          Generate LCOV coverage report"
            echo "  --keep-profraw  Keep raw .profraw files after merging"
            echo "  --all           Show all instrumented files (default: scheduler sources only)"
            exit 0
            ;;
        *) echo "Unknown flag: $arg"; exit 1 ;;
    esac
done

# Default to --html if no report format specified
if [[ $FLAG_HTML -eq 0 && $FLAG_LCOV -eq 0 ]]; then
    FLAG_HTML=1
fi

# --- Prerequisite checks ---
echo "=== Checking prerequisites ==="

if ! command -v llvm-profdata &>/dev/null; then
    echo "ERROR: llvm-profdata not found. Install compiler-rt / llvm-tools." >&2
    exit 1
fi

if ! command -v llvm-cov &>/dev/null; then
    echo "ERROR: llvm-cov not found. Install compiler-rt / llvm-tools." >&2
    exit 1
fi

COMPILER="${BPF_CLANG:-clang}"
if ! command -v "$COMPILER" &>/dev/null; then
    echo "ERROR: $COMPILER not found." >&2
    exit 1
fi

RT_DIR=$("$COMPILER" --print-runtime-dir 2>/dev/null || true)
if [[ -z "$RT_DIR" ]] || ! ls "$RT_DIR"/libclang_rt.profile*.a &>/dev/null; then
    echo "ERROR: libclang_rt.profile not found. Install compiler-rt." >&2
    echo "  Try: dnf install compiler-rt" >&2
    exit 1
fi

echo "  llvm-profdata: $(command -v llvm-profdata)"
echo "  llvm-cov:      $(command -v llvm-cov)"
echo "  compiler:      $(command -v "$COMPILER")"
echo "  runtime dir:   $RT_DIR"

# --- Clean previous coverage data ---
echo ""
echo "=== Cleaning previous coverage data ==="
rm -rf "$COVERAGE_OUT"
mkdir -p "$COVERAGE_OUT"

# Remove stale profraw files from the project tree
find "$PROJ_ROOT" -name '*.profraw' -delete 2>/dev/null || true

# Force a rebuild of the coverage-instrumented artifacts
echo ""
echo "=== Building with coverage instrumentation ==="
export SCX_SIM_COVERAGE=1
export LLVM_PROFILE_FILE="$COVERAGE_OUT/scxsim-%p-%m.profraw"

# Clean the build cache so we get a fresh instrumented build
cargo clean -p scx_simulator 2>/dev/null || true

# Build tests (this also triggers build.rs with SCX_SIM_COVERAGE=1)
cargo test -p scx_simulator --no-run --message-format=json 2>/dev/null \
    | tee "$COVERAGE_OUT/test-build.json" \
    | jq -r 'select(.executable != null) | .executable' \
    > "$COVERAGE_OUT/test-binaries.txt" || true

# Verify we found test binaries
if [[ ! -s "$COVERAGE_OUT/test-binaries.txt" ]]; then
    echo "ERROR: No test binaries found." >&2
    exit 1
fi

echo "  Found $(wc -l < "$COVERAGE_OUT/test-binaries.txt") test binary/binaries"

# --- Run tests ---
echo ""
echo "=== Running tests to generate coverage data ==="
cargo test -p scx_simulator 2>&1 | tee "$COVERAGE_OUT/test-output.txt"

# --- Merge profraw files ---
echo ""
echo "=== Merging profile data ==="
PROFRAW_FILES=()
while IFS= read -r -d '' f; do
    PROFRAW_FILES+=("$f")
done < <(find "$COVERAGE_OUT" "$PROJ_ROOT" -name '*.profraw' -print0 2>/dev/null)

if [[ ${#PROFRAW_FILES[@]} -eq 0 ]]; then
    echo "ERROR: No .profraw files found. Coverage instrumentation may not be working." >&2
    exit 1
fi

echo "  Found ${#PROFRAW_FILES[@]} profraw file(s)"
llvm-profdata merge -sparse "${PROFRAW_FILES[@]}" -o "$COVERAGE_OUT/merged.profdata"
echo "  Merged into $COVERAGE_OUT/merged.profdata"

# --- Find coverage-instrumented .so files ---
# The scheduler .so files contain the coverage mapping data
SO_FILES=()
while IFS= read -r bin; do
    # Find the OUT_DIR used by this build — it's the parent of the test binary's
    # deps directory, but we need the build script's OUT_DIR which contains
    # schedulers_cov/
    BUILD_OUT=$(dirname "$bin")
    # Search for coverage .so files in the build tree
    while IFS= read -r -d '' so; do
        SO_FILES+=("$so")
    done < <(find "$BUILD_OUT" -name 'libscx_*.so' -print0 2>/dev/null)
done < "$COVERAGE_OUT/test-binaries.txt"

# Also search the cargo target directory directly
while IFS= read -r -d '' so; do
    SO_FILES+=("$so")
done < <(find "$PROJ_ROOT/target" -path '*/schedulers_cov/libscx_*.so' -print0 2>/dev/null)

# Deduplicate
if [[ ${#SO_FILES[@]} -gt 0 ]]; then
    readarray -t SO_FILES < <(printf '%s\n' "${SO_FILES[@]}" | sort -u)
fi

# Build the -object flags for llvm-cov
OBJECT_FLAGS=()
# First object is the test binary itself (for static lib coverage)
FIRST_BIN=$(head -1 "$COVERAGE_OUT/test-binaries.txt")
OBJECT_FLAGS+=("$FIRST_BIN")
# Additional objects are the .so files
for so in "${SO_FILES[@]}"; do
    OBJECT_FLAGS+=("-object" "$so")
done

echo "  Coverage objects: ${#OBJECT_FLAGS[@]} (1 binary + ${#SO_FILES[@]} .so files)"

# --- Source filter ---
# By default, only show scheduler BPF source files (the code under test).
# Use --all to see everything including stubs, infrastructure, and headers.
SOURCE_FILTER=()
if [[ $FLAG_ALL -eq 0 ]]; then
    # Exclude infrastructure, stubs, headers, and wrappers — keep only
    # scheds/rust/scx_*/src/bpf/* and schedulers/simple/scx_simple.bpf.c
    SOURCE_FILTER+=(
        "-ignore-filename-regex=lib/scxtest/"
        "-ignore-filename-regex=csrc/sim_"
        "-ignore-filename-regex=scheds/include/"
        "-ignore-filename-regex=bpf_experimental\\.h"
        "-ignore-filename-regex=bpf_arena_common"
        "-ignore-filename-regex=libbpf-sys-.*/out/include/"
        "-ignore-filename-regex=schedulers/.*/wrapper\\.c"
        "-ignore-filename-regex=cosmos_main_patched\\.c"
        "-ignore-filename-regex=/intf\\.h$"
    )
fi

# --- Generate reports ---
echo ""
echo "=== Generating coverage reports ==="

if [[ $FLAG_HTML -eq 1 ]]; then
    echo "  Generating HTML report..."
    llvm-cov show "${OBJECT_FLAGS[@]}" \
        -instr-profile="$COVERAGE_OUT/merged.profdata" \
        "${SOURCE_FILTER[@]}" \
        -format=html \
        -output-dir="$COVERAGE_OUT/html" \
        -show-line-counts-or-regions \
        -show-instantiations=false \
        -Xdemangler=c++filt
    echo "  HTML report: $COVERAGE_OUT/html/index.html"
fi

if [[ $FLAG_LCOV -eq 1 ]]; then
    echo "  Generating LCOV report..."
    llvm-cov export "${OBJECT_FLAGS[@]}" \
        -instr-profile="$COVERAGE_OUT/merged.profdata" \
        "${SOURCE_FILTER[@]}" \
        -format=lcov \
        > "$COVERAGE_OUT/coverage.lcov"
    echo "  LCOV report: $COVERAGE_OUT/coverage.lcov"
fi

# Summary (always shown)
echo ""
echo "=== Coverage Summary ==="
llvm-cov report "${OBJECT_FLAGS[@]}" \
    -instr-profile="$COVERAGE_OUT/merged.profdata" \
    "${SOURCE_FILTER[@]}" \
    -show-region-summary=false

# --- Cleanup ---
if [[ $FLAG_KEEP_PROFRAW -eq 0 ]]; then
    rm -f "${PROFRAW_FILES[@]}"
    echo ""
    echo "  Cleaned up profraw files (use --keep-profraw to retain)"
fi

echo ""
echo "=== Done ==="
