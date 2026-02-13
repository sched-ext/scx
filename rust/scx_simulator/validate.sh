#!/bin/bash
# validate.sh - Local validation script for scx_simulator
# Run this before committing to ensure code quality.
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Running cargo clippy ==="
cargo clippy -p scx_simulator -- -D warnings

echo ""
echo "=== Running cargo test ==="
cargo test -p scx_simulator

echo ""
echo "=== All checks passed ==="
