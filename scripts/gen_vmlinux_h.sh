#!/bin/bash
set -euo pipefail

# Prerequisite
#
# * .config is ready in the linux repo
# * binary bpftool is installed
# * can `sudo apt install` cross-compile toolchains
#
# Example
#
# ./scripts/gen_vmlinux_h.sh /path/to/linux "$PWD/scheds/include/arch/"

BASEDIR=$(cd "$(dirname "$0")" && pwd)
LINUX_REPO=$(realpath "$1") # where the linux repo is located
INCLUDE_TARGET=$(realpath "$2") # target directory, e.g., /path/to/scx/sched/include/arch/
pushd ${LINUX_REPO}
HASH=$(git rev-parse HEAD)
SHORT_SHA=${HASH:0:12} # full SHA of the commit truncated to 12 chars
LINUX_VER=$(git describe --tags --abbrev=0 --match="v*")

# List of architectures and their corresponding cross-compilers
declare -A ARCHS
ARCHS=(
    [arm]="arm-linux-gnueabi-"
    [arm64]="aarch64-linux-gnu-"
    [mips]="mips64-linux-gnu-"
    [powerpc]="powerpc64le-linux-gnu-"
    [riscv]="riscv64-linux-gnu-"
    [s390]="s390x-linux-gnu-"
    [x86]="x86_64-linux-gnu-"
)
if grep ^ID=fedora /etc/os-release &> /dev/null; then
    ARCHS[arm]="arm-linux-gnu-"
fi

# Detect and install cross-compile toolchains based on the package manager
install_toolchains() {
    echo "Installing cross-compile toolchains..."

    if command -v apt &> /dev/null; then
        sudo apt update && sudo apt install -y \
            gcc-aarch64-linux-gnu gcc-x86-64-linux-gnu \
            gcc-arm-linux-gnueabi gcc-mips64-linux-gnuabi64 \
            gcc-powerpc64le-linux-gnu gcc-riscv64-linux-gnu \
            gcc-s390x-linux-gnu gcc-x86-64-linux-gnu
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y \
            gcc-aarch64-linux-gnu gcc-x86_64-linux-gnu \
            gcc-arm-linux-gnu gcc-mips64-linux-gnu \
            gcc-powerpc64le-linux-gnu gcc-riscv64-linux-gnu \
            gcc-s390x-linux-gnu
    elif command -v yum &> /dev/null; then
        sudo yum install -y \
            gcc-aarch64-linux-gnu gcc-x86_64-linux-gnu \
            gcc-arm-linux-gnu gcc-mips64-linux-gnuabi64 \
            gcc-powerpc64-linux-gnu gcc-riscv64-linux-gnu \
            gcc-s390x-linux-gnu gcc-x86_64-linux-gnu
    elif command -v pacman &> /dev/null; then
        sudo pacman -Sy --noconfirm \
            aarch64-linux-gnu-gcc x86_64-linux-gnu-gcc \
            arm-linux-gnueabi-gcc mips64-linux-gnu-gcc \
            powerpc64le-linux-gnu-gcc riscv64-linux-gnu-gcc \
            s390x-linux-gnu-gcc gcc
    elif command -v zypper &> /dev/null; then
        sudo zypper install -y \
            gcc-aarch64-linux-gnu gcc-x86_64-linux-gnu \
            gcc-arm-linux-gnueabi gcc-mips64-linux-gnuabi64 \
            gcc-powerpc64le-linux-gnu gcc-riscv64-linux-gnu \
            gcc-s390x-linux-gnu
    else
        echo "Unsupported package manager. Please install cross-compilers manually."
        exit 1
    fi
}

# Function to compile the kernel and generate vmlinux.h for a given architecture
generate_vmlinux_for_arch() {
    ARCH=$1
    CROSS_COMPILE=${ARCHS[$ARCH]}
    TARGET_DIR=${INCLUDE_TARGET}/${ARCH}
    OUTPUT_BASENAME="vmlinux-${LINUX_VER}-g${SHORT_SHA}.h"
    OUTPUT_FILE="${TARGET_DIR}/${OUTPUT_BASENAME}"
    mkdir -p ${TARGET_DIR}

    LOG="/tmp/${ARCH}.log"
    echo "" > ${LOG}
    echo "Writing compile logs to ${LOG}"

    rm -f .config.orig vmlinux
    if [ -e .config ]; then
        cp .config .config.orig
    else
        make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} KCFLAGS=-Wno-error defconfig &>> ${LOG}
    fi

    echo CONFIG_DEBUG_INFO_REDUCED=n >>.config
    echo CONFIG_DEBUG_INFO_DWARF4=y >>.config
    echo CONFIG_BPF_SYSCALL=y >>.config
    echo CONFIG_DEBUG_INFO_BTF=y >>.config
    echo CONFIG_GROUP_SCHED_BANDWIDTH=y >> .config
    echo CONFIG_GROUP_SCHED_WEIGHT=y >> .config
    echo CONFIG_CFS_BANDWIDTH=y >> .config
    echo CONFIG_BPF_JIT=y >>.config
    echo CONFIG_SCHED_CLASS_EXT=y >>.config
    echo CONFIG_CGROUP_SCHED=y >>.config
    echo CONFIG_FTRACE=y >>.config
    echo CONFIG_NUMA=y >>.config
    echo CONFIG_NUMA_BALANCING=y >>.config
    echo CONFIG_CPUSETS=y >>.config

    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} KCFLAGS=-Wno-error olddefconfig &>> ${LOG}
    make ARCH=${ARCH} CROSS_COMPILE=${CROSS_COMPILE} KCFLAGS=-Wno-error -j$(nproc) vmlinux &>> ${LOG}
    if [ -e .config.orig ]; then
        mv .config.orig .config
    else
        rm .config
    fi

    if [ -f ./vmlinux ]; then
        echo "Generating ${OUTPUT_FILE}..."
        bpftool btf dump file ./vmlinux format c > "${OUTPUT_FILE}"
        "${BASEDIR}/fixup_vmlinux_h.py" "${OUTPUT_FILE}"
        ln -fsT "${OUTPUT_BASENAME}" "${TARGET_DIR}/vmlinux.h"
        echo "${OUTPUT_FILE} generated successfully."
    else
        echo "Failed to generate vmlinux for ${ARCH}. Please check the compilation process."
    fi
}

if ! command -v bpftool &> /dev/null
then
    echo "bpftool could not be found. Please install it first."
    exit 1
fi

install_toolchains

echo "Start generating vmlinux.h for each arch: "
for ARCH in "${!ARCHS[@]}"; do
    echo "Processing architecture: $ARCH"
    generate_vmlinux_for_arch $ARCH
done

echo "All architectures processed."

popd

tar \
    --use-compress-program 'zstd -19' \
    --owner=0 --group=0 --numeric-owner \
    --format=ustar \
    --mtime='1970-01-01 00:00:00 UTC' \
    -cf "$BASEDIR/../rust/scx_utils/vmlinux.tar.zst" \
    -C "$BASEDIR/../scheds" vmlinux
