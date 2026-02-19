#!/bin/bash
# validate.sh - Local validation script for scx_simulator workspace
# Run this before committing to ensure code quality.
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Running cargo fmt --check ==="
cargo fmt --all -- --check

echo ""
echo "=== Running cargo clippy ==="
cargo clippy --all -- -D warnings

echo ""
echo "=== Running cargo test ==="
cargo test --all

echo ""
echo "=== All checks passed ==="
