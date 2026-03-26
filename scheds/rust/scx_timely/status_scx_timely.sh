#!/bin/sh
# Report whether scx_timely is installed, configured, and currently active.

set -e

BINARY_NAME="scx_timely"
BINARY_PATH="/usr/bin/${BINARY_NAME}"
SCX_DEFAULTS="/etc/default/scx"
SERVICE_NAME="scx"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; BOLD='\033[1m'; NC='\033[0m'

log_info()  { printf "${BLUE}[INFO]${NC}  %s\n" "$1"; }
log_ok()    { printf "${GREEN}[ OK ]${NC}  %s\n" "$1"; }
log_warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$1"; }
log_error() { printf "${RED}[ERR ]${NC}  %s\n" "$1" >&2; }

service_state() {
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'unavailable\n'
        return 0
    fi
    if systemctl is-active --quiet "${SERVICE_NAME}"; then
        printf 'active\n'
    elif systemctl is-failed --quiet "${SERVICE_NAME}"; then
        printf 'failed\n'
    else
        printf 'inactive\n'
    fi
}

service_enabled() {
    if ! command -v systemctl >/dev/null 2>&1; then
        printf 'unavailable\n'
        return 0
    fi
    if systemctl is-enabled --quiet "${SERVICE_NAME}" 2>/dev/null; then
        printf 'enabled\n'
    else
        printf 'disabled\n'
    fi
}

configured_scheduler() {
    if [ ! -r "$SCX_DEFAULTS" ]; then
        return 0
    fi
    sed -n "s/^SCX_SCHEDULER=//p" "$SCX_DEFAULTS" | tail -n 1
}

configured_flags() {
    if [ ! -r "$SCX_DEFAULTS" ]; then
        return 0
    fi
    sed -n "s/^SCX_FLAGS=//p" "$SCX_DEFAULTS" | tail -n 1
}

active_scheduler() {
    if [ -r /sys/kernel/sched_ext/root/ops ]; then
        cat /sys/kernel/sched_ext/root/ops 2>/dev/null || true
    fi
}

main() {
    _installed="no"
    _service_state=$(service_state)
    _service_enabled=$(service_enabled)
    _configured=$(configured_scheduler)
    _flags=$(configured_flags)
    _active=$(active_scheduler)
    _config_readable="yes"
    _rc=1

    if [ ! -r "$SCX_DEFAULTS" ]; then
        _config_readable="no"
    fi

    if [ -x "$BINARY_PATH" ]; then
        _installed="yes"
        log_ok "Installed binary: ${BINARY_PATH}"
        log_info "Installed version: $($BINARY_PATH --version 2>/dev/null || printf 'unknown')"
    else
        log_warn "Installed binary: missing (${BINARY_PATH})"
    fi

    log_info "scx.service state: ${_service_state}"
    log_info "scx.service enabled: ${_service_enabled}"

    if [ "$_config_readable" = "no" ]; then
        log_warn "Configured scheduler: unreadable (${SCX_DEFAULTS}); run with sudo to inspect it"
    elif [ -n "$_configured" ]; then
        log_info "Configured scheduler: ${_configured}"
    else
        log_warn "Configured scheduler: not set in ${SCX_DEFAULTS}"
    fi

    if [ -n "$_flags" ]; then
        log_info "Configured flags: ${_flags}"
    fi

    if [ -n "$_active" ]; then
        log_info "Active sched_ext scheduler: ${_active}"
    else
        log_warn "Active sched_ext scheduler: none"
    fi

    if [ "$_installed" = "yes" ] &&
       [ "$_service_state" = "active" ] &&
       [ "$_service_enabled" = "enabled" ] &&
       [ -n "$_active" ] &&
       (
           [ "$_config_readable" = "no" ] ||
           [ "$_configured" = "$BINARY_NAME" ]
       ) &&
       printf '%s' "$_active" | grep -q '^timely'; then
        log_ok "scx_timely is installed, configured, and currently active"
        _rc=0
    else
        log_warn "scx_timely is not fully active right now"
        if [ "$_configured" = "$BINARY_NAME" ] && [ -z "$_active" ]; then
            log_warn "Configured for scx_timely, but no active sched_ext scheduler is reported"
        elif [ "$_configured" = "$BINARY_NAME" ] && [ -n "$_active" ] &&
             ! printf '%s' "$_active" | grep -q '^timely'; then
            log_warn "Configured for scx_timely, but another scheduler is active"
        fi
    fi

    exit "$_rc"
}

main "$@"
