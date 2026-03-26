#!/usr/bin/env bash
# Compatibility wrapper for the generic benchmark runner.

set -euo pipefail

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$SCRIPT_DIR/benchmark.sh" --suite mini "$@"
