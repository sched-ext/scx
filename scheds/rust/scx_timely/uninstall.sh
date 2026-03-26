#!/bin/sh
# scx_timely uninstallation script
#
# Usage: sudo sh uninstall.sh [options]
#
# Options:
#   --force       Skip confirmation prompts
#   --dry-run     Print the actions without changing the system
#   --purge       Also remove the scx.service file
#   --help, -h    Print this help text and exit

set -e

BINARY_NAME="scx_timely"
SERVICE_NAME="scx"
BINARY_PATH="/usr/bin/${BINARY_NAME}"
SCX_DEFAULTS="/etc/default/scx"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"

FORCE=""
DRY_RUN=""
PURGE=""

while [ "$#" -gt 0 ]; do
    case "$1" in
        --force) FORCE="1"; shift ;;
        --dry-run) DRY_RUN="1"; shift ;;
        --purge) PURGE="1"; shift ;;
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

stop_scx_service() {
    if ! command -v systemctl >/dev/null 2>&1; then
        return 0
    fi
    run "systemctl stop '${SERVICE_NAME}' 2>/dev/null || true"
    run "systemctl disable '${SERVICE_NAME}' 2>/dev/null || true"
}

cleanup_scx_defaults() {
    if [ ! -f "$SCX_DEFAULTS" ]; then
        return 0
    fi
    if ! grep -q "^SCX_SCHEDULER=${BINARY_NAME}" "$SCX_DEFAULTS" 2>/dev/null; then
        return 0
    fi

    if [ -n "$DRY_RUN" ]; then
        log_info "(dry-run) Would clean ${SCX_DEFAULTS}"
        return 0
    fi

    _tmp=$(mktemp)
    grep -v "Managed by scx_timely installer" "$SCX_DEFAULTS" \
        | grep -v "^SCX_SCHEDULER=${BINARY_NAME}" \
        | grep -v "^SCX_FLAGS=" \
        > "$_tmp" || true
    cp "$_tmp" "$SCX_DEFAULTS"
    rm -f "$_tmp"
}

remove_files() {
    if [ -f "$BINARY_PATH" ]; then
        run "rm -f '$BINARY_PATH'"
    fi
    if [ -n "$PURGE" ] && [ -f "$SYSTEMD_SERVICE" ]; then
        run "rm -f '$SYSTEMD_SERVICE'"
    fi
}

main() {
    log_step "scx_timely uninstaller"
    check_root

    confirm "This will stop the scx service and remove scx_timely. Continue?" || exit 0

    stop_scx_service
    cleanup_scx_defaults
    remove_files
    run "systemctl daemon-reload 2>/dev/null || true"

    log_step "Done"
    log_ok "scx_timely has been removed"
}

main "$@"
