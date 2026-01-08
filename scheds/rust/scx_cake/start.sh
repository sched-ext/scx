#!/bin/bash
# Start script for scx_cake scheduler

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="$SCRIPT_DIR/target/release/scx_cake"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: scx_cake requires root privileges to load BPF scheduler"
    echo "Please run: sudo $0 $@"
    exit 1
fi

# Check if binary exists
if [ ! -f "$BINARY" ]; then
    echo "Error: Binary not found at $BINARY"
    echo "Please run ./build.sh first"
    exit 1
fi

# Check if kernel supports sched_ext
if [ ! -d "/sys/kernel/sched_ext" ]; then
    echo "Error: sched_ext not available in your kernel"
    echo "Make sure CONFIG_SCHED_CLASS_EXT=y is enabled"
    exit 1
fi

echo "=== Starting scx_cake scheduler ==="
echo "Current scheduler: $(cat /sys/kernel/sched_ext/state 2>/dev/null || echo 'disabled')"
echo ""

# Run with all arguments passed through
exec "$BINARY" "$@"
