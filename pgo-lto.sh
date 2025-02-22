#!/usr/bin/env bash
set -eou pipefail

PGO_TMPDIR=${1:-/tmp/pgo-data}
SCHED=${2:-scx_rustland}
PGO_DUR=${3:-30}

rm -rf "$PGO_TMPDIR"
mkdir -p "$PGO_TMPDIR"

RUSTFLAGS="-C profile-generate=$PGO_TMPDIR -C link-arg=-lgcov" \
    cargo build --release --bin "$SCHED"

echo "Running sched to generate PGO"
for i in {0..3}; do
	sudo "./target/release/$SCHED" &
	sleep "$PGO_DUR"
	sudo kill -9 $! || echo "$SCHED already dead"
	sleep 1
done

# Merge the `.profraw` files into a `.profdata` file
llvm-profdata merge --failure-mode=warn \
	-o "$PGO_TMPDIR/merged.profdata" \
	"$PGO_TMPDIR"

# Use the `.profdata` file for guiding optimizations
RUSTFLAGS="-Cprofile-use=$PGO_TMPDIR/merged.profdata" \
    cargo build --release --bin "$SCHED"

