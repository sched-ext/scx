#!/bin/bash

set -e

if [ $# -ne 1 ]; then
    echo "Usage: sync-to-kernel.sh KERNEL_TREE_TO_SYNC_TO" 1>&2
    exit 1
fi

# We sync these schedulers
rust_scheds=()
c_scheds=(scx_simple scx_qmap scx_central scx_flatcg)

headers=($(
    git ls-files include |
    grep -v include/lib |
    grep -v include/vmlinux |
    grep -v include/arch |
    grep -v '\.gitignore$'
))

scheds=()
for rust_sched in ${rust_scheds[@]}; do
    scheds+=($(git ls-files rust/${rust_sched} | grep -Ev 'LICENSE'))
done
for c_sched in ${c_scheds[@]}; do
    scheds+=($(git ls-files c/${c_sched}*))
done

kernel="$1/tools/sched_ext"

echo "Syncing ${#headers[@]} headers and ${#scheds[@]} scheduler source files to $kernel"

srcs=("${headers[@]}" "${scheds[@]}")
dsts=()

# Header paths are the same relative to the base directories.
for file in ${headers[@]}; do
    dsts+=("$kernel/${file}")
done

# Sched files should drop the first directory component. ie.
# c/scx_simple.bpf.c should be synced to
# $kernel/scx_simple.bpf.c.
for file in ${scheds[@]}; do
    dsts+=("$kernel/${file#*/}")
done

## debug
# for ((i=0;i<${#srcs[@]};i++)); do
#    echo "${srcs[i]} -> ${dsts[i]}"
# done

nr_missing=0
nr_skipped=0
nr_synced=0
for ((i=0;i<${#srcs[@]};i++)); do
    src="${srcs[i]}"
    dst="${dsts[i]}"
    orig="$src"

    if [ ! -f "$dst" ]; then
        echo "WARNING: $dst does not exist" 1>&2
        nr_missing=$((nr_missing+1))
        continue
    fi

    #
    # As scx_utils is in this repo, rust schedulers point directly to
    # the source in the tree. As they break outside this tree, drop them
    # before syncing Cargo.toml files.
    #
    if [[ "$src" == */Cargo.toml ]]; then
        tmp=$(mktemp)
        sed -r 's/^scx_utils =.*version\s*=\s*"([^"]*)".*$/scx_utils = \"\1"/' < "$src" > "$tmp"
        src="$tmp"
    fi

    if cmp -s "$src" "$dst"; then
        nr_skipped=$((nr_skipped+1))
        continue
    fi

    if [[ "$orig" == */Cargo.toml ]]; then
        echo "Syncing $orig (dropped path from scx_utils dependency)"
    else
        echo "Syncing $orig"
    fi

    mkdir -p "$(dirname "$dst")"
    cp -f "$src" "$dst"
    nr_synced=$((nr_synced+1))
done

echo
echo "Synced $nr_synced updated files"
echo "Skipped $nr_skipped unchanged and created $nr_missing new files"
