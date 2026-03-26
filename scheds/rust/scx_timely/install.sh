#!/bin/sh
# scx_timely installation script
#
# Supported distros : CachyOS, Arch Linux, Ubuntu 24.04+, Debian 12+,
#                     and other systemd-based Linux distributions with a
#                     sched_ext-capable kernel.
# Usage             : sudo sh install.sh [options]
#
# Options:
#   --build-from-source   Compile the binary locally (default behavior)
#   --dry-run             Print the actions without changing the system
#   --force               Skip confirmation prompts
#   --flags "..."         Custom scheduler flags written to /etc/default/scx
#                         (default: --mode desktop)
#   --help, -h            Print this help text and exit

set -e

BINARY_NAME="scx_timely"
SERVICE_NAME="scx"
BINARY_PATH="/usr/bin/${BINARY_NAME}"
SCX_DEFAULTS="/etc/default/scx"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_SCX_FLAGS="--mode desktop"

BUILD_FROM_SOURCE="1"
DRY_RUN=""
FORCE=""
SCX_FLAGS="${SCX_FLAGS:-$DEFAULT_SCX_FLAGS}"
BUILD_MIRROR_DIR=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --build-from-source)  BUILD_FROM_SOURCE="1"; shift ;;
        --dry-run)            DRY_RUN="1"; shift ;;
        --force)              FORCE="1"; shift ;;
        --flags)              SCX_FLAGS="$2"; shift 2 ;;
        --help|-h)
            sed -n '/^# Options:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,2\}//'
            exit 0
            ;;
        *)
            printf '[ERR ] Unknown option: %s\n' "$1" >&2
            exit 1
            ;;
    esac
done

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { printf "${BLUE}[INFO]${NC}  %s\n" "$1"; }
log_ok()    { printf "${GREEN}[ OK ]${NC}  %s\n" "$1"; }
log_warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
log_error() { printf "${RED}[ERR ]${NC}  %s\n" "$1" >&2; }
log_step()  { printf "\n${BOLD}${CYAN}──── %s ────${NC}\n" "$1"; }

run() {
    if [ -n "$DRY_RUN" ]; then
        printf "${YELLOW}[DRY ]${NC}  %s\n" "$*"
    else
        eval "$@"
    fi
}

cleanup_build_mirror() {
    if [ -n "${BUILD_MIRROR_DIR}" ] && [ -d "${BUILD_MIRROR_DIR}" ]; then
        rm -rf "${BUILD_MIRROR_DIR}"
    fi
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        log_error "Run as root: sudo sh $0 $*"
        exit 1
    fi
}

confirm() {
    [ -n "$FORCE" ] && return 0
    printf "%s [y/N]: " "$1"
    read -r _ans
    case "$_ans" in y|Y) return 0 ;; *) return 1 ;; esac
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        # shellcheck source=/dev/null
        . /etc/os-release
        case "${ID:-}" in
            cachyos) echo "cachyos"; return ;;
            arch)    echo "arch"; return ;;
            ubuntu)  echo "ubuntu"; return ;;
            debian)  echo "debian"; return ;;
        esac
        case "${ID_LIKE:-}" in
            *arch*) echo "arch"; return ;;
            *ubuntu*|*debian*) echo "debian"; return ;;
        esac
    fi
    echo "generic"
}

install_deps_arch() {
    _pkgs="clang llvm libbpf libelf libseccomp pkgconf curl"
    log_info "Installing dependencies via pacman..."
    run "pacman -S --noconfirm --needed ${_pkgs}"
}

install_deps_debian() {
    log_info "Installing dependencies via apt..."
    run "apt-get update -qq"
    run "apt-get install -y --no-install-recommends clang llvm libclang-dev libbpf-dev libelf-dev libseccomp-dev pkg-config curl"
}

install_rust_if_missing() {
    if command -v cargo >/dev/null 2>&1; then
        log_ok "Rust toolchain already present: $(cargo --version)"
        return 0
    fi
    log_info "Installing Rust via rustup..."
    run "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable"
}

check_sched_ext_support() {
    _cfg="/boot/config-$(uname -r)"
    if [ -f "$_cfg" ] && grep -q "CONFIG_SCHED_CLASS_EXT=y" "$_cfg" 2>/dev/null; then
        return 0
    fi
    if command -v zcat >/dev/null 2>&1 \
       && zcat /proc/config.gz 2>/dev/null | grep -q "CONFIG_SCHED_CLASS_EXT=y"; then
        return 0
    fi
    [ -d /sys/kernel/sched_ext ]
}

build_from_source() {
    _distro="$1"
    _src=$(cd "$(dirname "$0")"; pwd)
    _build_src="$_src"

    case "$_distro" in
        cachyos|arch)  install_deps_arch ;;
        ubuntu|debian) install_deps_debian ;;
        *) log_warn "Unknown distro. Building without automatic dependency installation." ;;
    esac

    install_rust_if_missing
    export PATH="${HOME}/.cargo/bin:${PATH}"

    if printf '%s' "$_src" | grep -q ' '; then
        BUILD_MIRROR_DIR=$(mktemp -d /tmp/scx_timely-build.XXXXXX)
        log_info "Source path contains spaces; building from temporary mirror ${BUILD_MIRROR_DIR}"
        (
            cd "$_src"
            tar --exclude='./.git' --exclude='./target' --exclude='./benchmark-results' -cf - .
        ) | (
            cd "$BUILD_MIRROR_DIR"
            tar -xf -
        )
        _build_src="$BUILD_MIRROR_DIR"
    fi

    run "cargo build --release --manifest-path \"${_build_src}/Cargo.toml\""

    _target_dir=$(cargo metadata --format-version 1 --no-deps --manifest-path "${_build_src}/Cargo.toml" \
        | sed -n 's/.*\"target_directory\":\"\([^\"]*\)\".*/\1/p')
    [ -n "$_target_dir" ] || _target_dir="${_build_src}/target"

    if [ ! -f "${_target_dir}/release/${BINARY_NAME}" ]; then
        log_error "Built binary not found at ${_target_dir}/release/${BINARY_NAME}"
        exit 1
    fi

    _staged="${BINARY_PATH}.new.$$"
    run "cp \"${_target_dir}/release/${BINARY_NAME}\" \"${_staged}\""
    run "chmod 755 \"${_staged}\""
    run "mv -f \"${_staged}\" \"${BINARY_PATH}\""
    log_ok "Installed ${BINARY_PATH}"
}

install_scx_service_file() {
    log_info "Writing ${SYSTEMD_SERVICE} ..."
    if [ -n "$DRY_RUN" ]; then
        log_info "(dry-run) Would write scx.service"
        return
    fi

    cat > "${SYSTEMD_SERVICE}" <<'SVCEOF'
[Unit]
Description=Start scx_timely sched_ext scheduler
Documentation=https://github.com/galpt/scx_timely
ConditionPathIsDirectory=/sys/kernel/sched_ext
After=multi-user.target

[Service]
Type=simple
EnvironmentFile=/etc/default/scx
ExecStart=/bin/sh -c 'exec ${SCX_SCHEDULER_OVERRIDE:-$SCX_SCHEDULER} ${SCX_FLAGS_OVERRIDE:-$SCX_FLAGS}'
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=scx
RuntimeDirectory=scx/root
RuntimeDirectoryMode=0755
UMask=0111

[Install]
WantedBy=multi-user.target
SVCEOF
    log_ok "Service file written"
}

configure_scx_defaults() {
    _flags="${SCX_FLAGS:-$DEFAULT_SCX_FLAGS}"
    log_info "Configuring ${SCX_DEFAULTS} ..."

    if [ -n "$DRY_RUN" ]; then
        log_info "(dry-run) Would write ${SCX_DEFAULTS}"
        return 0
    fi

    _tmp_cfg=$(mktemp)
    if [ -f "$SCX_DEFAULTS" ]; then
        grep -v "^SCX_SCHEDULER=" "$SCX_DEFAULTS" \
            | grep -v "^SCX_FLAGS=" \
            > "$_tmp_cfg" || true
    fi
    cat >> "$_tmp_cfg" <<EOF

# Managed by scx_timely installer.
SCX_SCHEDULER=${BINARY_NAME}
SCX_FLAGS='${_flags}'
EOF
    cp "$_tmp_cfg" "$SCX_DEFAULTS"
    rm -f "$_tmp_cfg"
    log_ok "${SCX_DEFAULTS} updated"
}

enable_scx_service() {
    log_info "Reloading systemd and enabling scx.service ..."
    run "systemctl daemon-reload"
    run "systemctl enable ${SERVICE_NAME}"
    run "systemctl restart ${SERVICE_NAME}"
    log_ok "scx.service is enabled and running"
}

main() {
    log_step "scx_timely installer"
    check_root
    trap cleanup_build_mirror EXIT HUP INT TERM

    _distro=$(detect_distro)
    log_info "Distribution : ${_distro}"
    [ -n "$DRY_RUN" ] && log_warn "DRY-RUN mode — no changes will be made"

    log_step "Checking kernel sched_ext support"
    if check_sched_ext_support; then
        log_ok "Kernel $(uname -r) reports sched_ext support"
    else
        log_warn "Could not confirm sched_ext support for kernel $(uname -r)"
        confirm "Continue installation anyway?" || exit 0
    fi

    log_step "Installing binary"
    build_from_source "$_distro"

    log_step "Configuring scx service"
    install_scx_service_file
    configure_scx_defaults
    enable_scx_service

    log_step "Done"
    log_ok "scx_timely is installed"
    log_info "Configured flags: ${SCX_FLAGS}"
}

main "$@"
