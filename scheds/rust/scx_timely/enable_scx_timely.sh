#!/bin/sh
# Re-assert scx_timely as the configured sched_ext scheduler and restart scx.service.
#
# Usage: sudo sh enable_scx_timely.sh [options]
#
# Options:
#   --flags "..."   Scheduler flags written to /etc/default/scx (default: --mode desktop)
#   --dry-run       Print the actions without changing the system
#   --force         Skip confirmation prompts
#   --help, -h      Print this help text and exit

set -e

BINARY_NAME="scx_timely"
BINARY_PATH="/usr/bin/${BINARY_NAME}"
SERVICE_NAME="scx"
SCX_DEFAULTS="/etc/default/scx"
SYSTEMD_SERVICE="/etc/systemd/system/${SERVICE_NAME}.service"
DEFAULT_SCX_FLAGS="--mode desktop"

DRY_RUN=""
FORCE=""
SCX_FLAGS="${SCX_FLAGS:-$DEFAULT_SCX_FLAGS}"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --flags)   SCX_FLAGS="$2"; shift 2 ;;
        --dry-run) DRY_RUN="1"; shift ;;
        --force)   FORCE="1"; shift ;;
        --help|-h)
            sed -n '/^# Usage:/,/^[^#]/p' "$0" | grep '^#' | sed 's/^# \{0,2\}//'
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

require_installation() {
    if [ ! -x "$BINARY_PATH" ]; then
        log_error "${BINARY_PATH} not found. Install scx_timely first."
        exit 1
    fi
    if [ ! -f "$SYSTEMD_SERVICE" ]; then
        log_error "${SYSTEMD_SERVICE} not found. Run install.sh first."
        exit 1
    fi
}

configure_scx_defaults() {
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

# Managed by scx_timely enable helper.
SCX_SCHEDULER=${BINARY_NAME}
SCX_FLAGS='${SCX_FLAGS}'
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
    log_ok "scx.service is enabled and restarted"
}

show_active_scheduler() {
    if [ -n "$DRY_RUN" ]; then
        log_info "(dry-run) Would wait for an active sched_ext scheduler"
        return 0
    fi

    _attempt=0
    while [ "$_attempt" -lt 20 ]; do
        if [ -r /sys/kernel/sched_ext/root/ops ]; then
            _active=$(cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true)
            if [ -n "$_active" ]; then
                log_ok "Current sched_ext scheduler: ${_active}"
                return 0
            fi
        fi
        _attempt=$((_attempt + 1))
        sleep 0.25
    done

    log_warn "No active sched_ext scheduler reported in /sys/kernel/sched_ext/root/ops after restart"
    return 1
}

main() {
    log_step "Enable scx_timely"
    check_root
    require_installation

    [ -n "$DRY_RUN" ] && log_warn "DRY-RUN mode — no changes will be made"
    confirm "Configure scx.service to run scx_timely with flags '${SCX_FLAGS}'?" || exit 0

    configure_scx_defaults
    enable_scx_service
    show_active_scheduler || true

    log_step "Done"
    log_ok "scx_timely is configured as the primary scheduler for scx.service"
}

main "$@"
