#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: sync-to-kernel.sh KERNEL_TREE_TO_SYNC_TO" 1>&2
    exit 1
fi

headers="

kernel="$1/tools/sched_ext"
headers="$kernel/include"
c_scheds="$kernel/*.[hc]"
files=(include/common/* kernel-examples/*.[hc])

echo "Syncing ${#files[@]} files from \"$1\""

nr_missing=0
for i in "${files[@]}"; do
    base=$(basename "$i")
    if [ ! -f "$kernel/$base" ]; then
	echo "ERROR: $base does not exist in $kernel" 1>&2
	nr_missing=$((nr_missing+1))
    fi
done

if [ $nr_missing -gt 0 ]; then
    exit 1
fi

nr_skipped=0
for i in "${files[@]}"; do
    base=$(basename "$i")
    if cmp -s "$kernel/$base" $i; then
	nr_skipped=$((nr_skipped+1))
	continue
    fi
    echo "Syncing $base"
    cp -f "$kernel/$base" $i
done

echo "Skipped $nr_skipped files as they are unchanged"
