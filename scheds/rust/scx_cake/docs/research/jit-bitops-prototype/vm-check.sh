#!/usr/bin/env bash
# Diagnostic VM only; no scheduler is attached and no host privilege is needed.
set -euo pipefail
if (( $# != 4 )); then
    echo "Usage: $0 BUILD_ROOT RESULTS_ROOT NEW_RUN_NAME native|fallback" >&2
    exit 2
fi
build_root=$(realpath "$1")
results_root=$(realpath "$2")
run_name=$3
case "$run_name" in ''|*[!a-zA-Z0-9_-]*) exit 2;; esac
case "$4" in
    native) cpu=max ;;
    fallback) cpu=qemu64 ;;
    *) exit 2 ;;
esac
test ! -e "$results_root/$run_name"
test ! -e "$results_root/$run_name.log"
mkdir -p "$build_root/rootfs/results"
export PATH="$build_root/venv/bin:$PATH"
timeout 120 vng --verbose --run "$build_root/build" \
    --root "$build_root/rootfs" --cwd "$build_root/rootfs/work" \
    --disable-kvm --disable-microvm --qemu-opts="-cpu $cpu" \
    --user root --cpus 2 --memory 2G --force-9p \
    --rwdir "/results=$results_root" \
    --append 'console=ttyS0,115200 panic=-1 oops=panic loglevel=5' \
    --exec "exec >/dev/console 2>&1; /work/bitops-run /results/$run_name 10 2 && /work/selftest-run /work/scalar_bitops.bpf.o; exit \$?" \
    > "$results_root/$run_name.log" 2>&1
