#!/bin/bash
# Test script for validating the selective matrix generation

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
cd "$REPO_ROOT"

echo "=== Test 1: Non-PR context (should test all) ==="
unset GITHUB_BASE_REF
python3 .github/include/list-integration-tests.py sched_ext/for-next > /tmp/test-matrix.txt 2>&1
MATRIX_COUNT=$(python3 -c "import json; data=open('/tmp/test-matrix.txt').read(); matrix=json.loads(data.split('matrix=')[1]); print(len(matrix))")
echo "Matrix entries: $MATRIX_COUNT"
if [ "$MATRIX_COUNT" -lt 10 ]; then
    echo "ERROR: Expected at least 10 matrix entries, got $MATRIX_COUNT"
    exit 1
fi
echo "PASS"
echo

echo "=== Test 2: Only scx_chaos changed ==="
export GITHUB_BASE_REF="main"
# Create a test branch with only scx_chaos changes
git branch -D test-selective-chaos 2>/dev/null || true
git checkout -b test-selective-chaos
touch scheds/rust/scx_chaos/src/main.rs
git add scheds/rust/scx_chaos/src/main.rs
git commit -m "Test: modify scx_chaos" --allow-empty
python3 .github/include/list-integration-tests.py sched_ext/for-next > /tmp/test-matrix2.txt 2>&1
MATRIX_COUNT=$(python3 -c "import json; data=open('/tmp/test-matrix2.txt').read(); matrix=json.loads(data.split('matrix=')[1]); print(len(matrix))")
echo "Matrix entries: $MATRIX_COUNT"
if [ "$MATRIX_COUNT" -ne 1 ]; then
    echo "ERROR: Expected 1 matrix entry for scx_chaos, got $MATRIX_COUNT"
    cat /tmp/test-matrix2.txt
    exit 1
fi
SCHED_NAME=$(python3 -c "import json; data=open('/tmp/test-matrix2.txt').read(); matrix=json.loads(data.split('matrix=')[1]); print(matrix[0]['name'])")
if [ "$SCHED_NAME" != "scx_chaos" ]; then
    echo "ERROR: Expected scx_chaos, got $SCHED_NAME"
    exit 1
fi
git reset --hard HEAD~1
git checkout main
git branch -D test-selective-chaos
echo "PASS"
echo

echo "=== Test 3: Core library changed (should test all) ==="
export GITHUB_BASE_REF="main"
git branch -D test-selective-core 2>/dev/null || true
git checkout -b test-selective-core
touch rust/scx_utils/src/lib.rs
git add rust/scx_utils/src/lib.rs
git commit -m "Test: modify scx_utils" --allow-empty
python3 .github/include/list-integration-tests.py sched_ext/for-next > /tmp/test-matrix3.txt 2>&1
MATRIX_COUNT=$(python3 -c "import json; data=open('/tmp/test-matrix3.txt').read(); matrix=json.loads(data.split('matrix=')[1]); print(len(matrix))")
echo "Matrix entries: $MATRIX_COUNT"
if [ "$MATRIX_COUNT" -lt 10 ]; then
    echo "ERROR: Expected at least 10 matrix entries (all schedulers), got $MATRIX_COUNT"
    exit 1
fi
git reset --hard HEAD~1
git checkout main
git branch -D test-selective-core
echo "PASS"
echo

echo "=== All tests passed! ==="
