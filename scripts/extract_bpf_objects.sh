#!/usr/bin/env bash
#
# Extract BPF objects from scheduler binaries using llvm-readobj
#

set -euo pipefail
shopt -s lastpipe

BINARY="$1"
OUTPUT_DIR="$2"

if [ -z "${BINARY}" ] || [ -z "${OUTPUT_DIR}" ]; then
    echo "Usage: $0 <scheduler_binary> <output_dir>"
    exit 1
fi

if [ ! -f "${BINARY}" ]; then
    echo "Error: Binary ${BINARY} not found"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

if ! command -v llvm-readobj >/dev/null 2>&1; then
    echo "Error: llvm-readobj not found. Please install LLVM tools."
    exit 1
fi

EXTRACTED_COUNT=0

llvm-readobj --elf-output-style=JSON --symbols "$BINARY" \
  | jq -c '.[0].Symbols[].Symbol | select(.Section.Name == ".bpf.objs") | {name: .Name.Name, offset: .Value, size: .Size}' \
  | while read -r line; do
    name=$(jq -r .name <<< "$line")
    offset=$(jq -r .offset <<< "$line")
    size=$(jq -r .size <<< "$line")

    echo "Extracting '$name.bpf.o'..."

    dd if="$BINARY" of="$OUTPUT_DIR/$name.bpf.o" bs=4M iflag=skip_bytes,count_bytes skip="$offset" count="$size" status=none
    ((EXTRACTED_COUNT++)) || true
done

echo "Successfully extracted $EXTRACTED_COUNT BPF object files to ${OUTPUT_DIR}"
