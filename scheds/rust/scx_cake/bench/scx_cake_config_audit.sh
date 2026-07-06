#!/usr/bin/env bash
# Inventory scx_cake runtime knobs and generate benchmark config plans.
set -Eeuo pipefail
umask 077

usage() {
    cat <<'USAGE'
Usage:
  scheds/rust/scx_cake/bench/scx_cake_config_audit.sh [--plan=quick|wide|full-factorial] [--out DIR]

Creates:
  audit.md
  config_options.tsv
  config_plan.tsv
  scx_cake_help.txt, when the selected scx_cake binary exists

Environment:
  SCX_CAKE_BIN=./target/debug/scx_cake
  SCX_CAKE_BENCH_ROOT=.scx_cake_bench
  SCX_CAKE_CONFIG_AUDIT_OUT=.scx_cake_bench/config-audit/<timestamp>
  SCX_CAKE_CONFIG_PLAN=quick

Plans:
  quick           one-axis-at-a-time plus a few likely interactions
  wide            broader but still human-reviewable interaction plan
  full-factorial  every known runtime A/B combination; do not run first
USAGE
}

die() {
    echo "error: $*" >&2
    exit 1
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SCX_CAKE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
REPO_ROOT="$(git -C "${SCX_CAKE_DIR}" rev-parse --show-toplevel 2>/dev/null || (cd "${SCX_CAKE_DIR}/../../.." && pwd))"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BENCH_ROOT="${SCX_CAKE_BENCH_ROOT:-${REPO_ROOT}/.scx_cake_bench}"

PLAN="${SCX_CAKE_CONFIG_PLAN:-quick}"
OUT_DIR="${SCX_CAKE_CONFIG_AUDIT_OUT:-${BENCH_ROOT}/config-audit/${STAMP}_${PLAN}}"
SCX_BIN="${SCX_CAKE_BIN:-${REPO_ROOT}/target/debug/scx_cake}"

while [[ "$#" -gt 0 ]]; do
    case "$1" in
        --plan=*)
            PLAN="${1#*=}"
            ;;
        --plan)
            shift
            [[ "$#" -gt 0 ]] || die "--plan requires a value"
            PLAN="$1"
            ;;
        --out=*)
            OUT_DIR="${1#*=}"
            ;;
        --out)
            shift
            [[ "$#" -gt 0 ]] || die "--out requires a directory"
            OUT_DIR="$1"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            usage
            die "unknown argument: $1"
            ;;
    esac
    shift
done

case "${PLAN}" in
    quick|wide|full-factorial) ;;
    *) die "--plan must be quick, wide, or full-factorial" ;;
esac

if [[ -L "${OUT_DIR}" ]]; then
    die "output directory must not be a symlink: ${OUT_DIR}"
fi
mkdir -p -m 0700 "${OUT_DIR}"

declare -a TMP_FILES=()

safe_tmp_file() {
    local result_var="$1"
    local dest="$2"
    local created_tmp

    created_tmp="$(mktemp -p "${OUT_DIR}" ".$(basename "${dest}").tmp.XXXXXX")" ||
        die "failed to create temporary output for ${dest}"
    TMP_FILES+=("${created_tmp}")
    printf -v "${result_var}" '%s' "${created_tmp}"
}

safe_replace_from_tmp() {
    local tmp="$1"
    local dest="$2"

    if [[ -e "${dest}" && ! -f "${dest}" && ! -L "${dest}" ]]; then
        rm -f "${tmp}"
        die "refusing to replace non-regular output path: ${dest}"
    fi
    mv -fT -- "${tmp}" "${dest}" ||
        die "failed to replace output file: ${dest}"
}

safe_write_file() {
    local dest="$1"
    local tmp

    safe_tmp_file tmp "${dest}"
    if ! cat >"${tmp}"; then
        rm -f "${tmp}"
        die "failed to write temporary output for ${dest}"
    fi
    safe_replace_from_tmp "${tmp}" "${dest}"
}

give_output_to_sudo_user() {
    local path="$1"
    if [[ "${EUID}" -eq 0 && -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" && "${SUDO_UID}" != "0" ]]; then
        [[ -e "${path}" && ! -L "${path}" ]] || return 0
        chown -R "${SUDO_UID}:${SUDO_GID}" -- "${path}" 2>/dev/null || true
    fi
}

cleanup() {
    local status=$?
    rm -f "${TMP_FILES[@]}" 2>/dev/null || true
    give_output_to_sudo_user "${OUT_DIR}"
    return "${status}"
}
trap cleanup EXIT

OPTIONS="${OUT_DIR}/config_options.tsv"
CONFIG_PLAN="${OUT_DIR}/config_plan.tsv"
REPORT="${OUT_DIR}/audit.md"
HELP_FILE="${OUT_DIR}/scx_cake_help.txt"
safe_tmp_file CONFIG_PLAN_TMP "${CONFIG_PLAN}"

write_options() {
    safe_write_file "${OPTIONS}" <<'EOF'
axis	values	default	notes
profile	esports,gaming,balanced,legacy	gaming	Debug runtime preset; release builds bake this at compile time.
quantum	750,1000,1500,2000,4000	auto from profile	Debug runtime override; release builds bake SCX_CAKE_QUANTUM_US.
queue-policy	local,llc-vtime	local	Debug runtime A/B; release builds bake SCX_CAKE_QUEUE_POLICY.
storm-guard	off,shadow,shield,full	shield	shadow records candidates; shield is conservative enforcement; full is broad benchmark-only enforcement.
busy-wake-kick	policy,preempt,idle	policy	Same-CPU busy wake kick behavior.
wake-chain-locality	false,true	false	Learned wake-chain locality guard.
learned-locality	false,true	false	Arena-backed home/core/primary steering after enough task history.
verbose	false,true	false	Needed for Cake diagnostics; benchmark harness runs headless verbose mode.
diag-period	2,5,60	60	Headless diagnostic write interval in seconds.
EOF
}

add_config() {
    local label="$1"
    local args="$2"
    local reason="$3"
    printf '%s\t%s\t%s\n' "${label}" "${args}" "${reason}" >>"${CONFIG_PLAN_TMP}"
}

write_quick_plan() {
    add_config baseline '--profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'record-only control for diagnostics and benchmark baseline'
    add_config storm-shield '--profile gaming --queue-policy llc-vtime --storm-guard shield --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'conservative storm enforcement against the shadow control'
    add_config queue-local '--profile gaming --queue-policy local --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'test whether local-only fallback fixes or hurts chart workloads'
    add_config kick-preempt '--profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick preempt --wake-chain-locality=false --learned-locality=false' 'test aggressive same-CPU wake preemption'
    add_config kick-idle '--profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick idle --wake-chain-locality=false --learned-locality=false' 'test gentler same-CPU wake kicks'
    add_config profile-esports '--profile esports --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'shorter quantum latency/overhead tradeoff'
    add_config profile-balanced '--profile balanced --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'longer quantum throughput/latency tradeoff'
    add_config profile-legacy '--profile legacy --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'longest preset quantum throughput/overhead tradeoff'
    add_config wake-chain-locality '--profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=true --learned-locality=false' 'test learned wake-chain locality guard'
    add_config learned-locality '--profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=false --learned-locality=true' 'test learned locality steering'
    add_config shield-local '--profile gaming --queue-policy local --storm-guard shield --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'interaction: conservative storm guard plus local fallback'
    add_config shield-preempt '--profile gaming --queue-policy llc-vtime --storm-guard shield --busy-wake-kick preempt --wake-chain-locality=false --learned-locality=false' 'interaction: storm guard plus aggressive wake preempt'
}

write_wide_plan() {
    write_quick_plan
    add_config shield-idle '--profile gaming --queue-policy llc-vtime --storm-guard shield --busy-wake-kick idle --wake-chain-locality=false --learned-locality=false' 'interaction: storm guard plus gentle wake kick'
    add_config esports-shield '--profile esports --queue-policy llc-vtime --storm-guard shield --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'interaction: lower quantum plus shield'
    add_config balanced-shield '--profile balanced --queue-policy llc-vtime --storm-guard shield --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'interaction: longer quantum plus shield'
    add_config local-preempt '--profile gaming --queue-policy local --storm-guard shadow --busy-wake-kick preempt --wake-chain-locality=false --learned-locality=false' 'interaction: local fallback plus preempt'
    add_config local-idle '--profile gaming --queue-policy local --storm-guard shadow --busy-wake-kick idle --wake-chain-locality=false --learned-locality=false' 'interaction: local fallback plus idle kick'
    add_config locality-both '--profile gaming --queue-policy llc-vtime --storm-guard shadow --busy-wake-kick policy --wake-chain-locality=true --learned-locality=true' 'interaction: both learned locality systems'
    add_config full-observation '--profile gaming --queue-policy llc-vtime --storm-guard full --busy-wake-kick policy --wake-chain-locality=false --learned-locality=false' 'broad storm A/B only; compare carefully against shadow'
}

write_full_factorial_plan() {
    local profile queue storm kick wake learned label args
    for profile in esports gaming balanced legacy; do
        for queue in llc-vtime local; do
            for storm in off shadow shield full; do
                for kick in policy preempt idle; do
                    for wake in false true; do
                        for learned in false true; do
                            label="${profile}_${queue}_storm-${storm}_kick-${kick}_wake-${wake}_learned-${learned}"
                            args="--profile ${profile} --queue-policy ${queue} --storm-guard ${storm} --busy-wake-kick ${kick} --wake-chain-locality=${wake} --learned-locality=${learned}"
                            add_config "${label}" "${args}" 'full-factorial generated combination'
                        done
                    done
                done
            done
        done
    done
}

write_options
printf 'label\targs\trationale\n' >"${CONFIG_PLAN_TMP}"
case "${PLAN}" in
    quick)
        write_quick_plan
        ;;
    wide)
        write_wide_plan
        ;;
    full-factorial)
        write_full_factorial_plan
        ;;
esac
safe_replace_from_tmp "${CONFIG_PLAN_TMP}" "${CONFIG_PLAN}"

if [[ -x "${SCX_BIN}" ]]; then
    safe_tmp_file HELP_TMP "${HELP_FILE}"
    "${SCX_BIN}" --help >"${HELP_TMP}" 2>&1 || true
    safe_replace_from_tmp "${HELP_TMP}" "${HELP_FILE}"
else
    safe_write_file "${HELP_FILE}" <<EOF
scx_cake binary not executable: ${SCX_BIN}
Build first with: cargo build -p scx_cake
EOF
fi

plan_count="$(awk 'NR > 1 { n++ } END { print n + 0 }' "${CONFIG_PLAN}")"

safe_write_file "${REPORT}" <<EOF
# scx_cake Configuration Audit

- Started UTC: ${STAMP}
- Plan: ${PLAN}
- Configurations: ${plan_count}
- scx_cake binary: ${SCX_BIN}
- Output: ${OUT_DIR}

## Files

- \`${OPTIONS}\`
- \`${CONFIG_PLAN}\`
- \`${HELP_FILE}\`

## Important Boundary

Debug builds can change profile, quantum, queue policy, storm guard, and busy-wake kick at runtime. Release builds bake the hot-path values at compile time, so release A/B work must rebuild with SCX_CAKE_PROFILE, SCX_CAKE_QUANTUM_US, SCX_CAKE_QUEUE_POLICY, SCX_CAKE_STORM_GUARD, or SCX_CAKE_BUSY_WAKE_KICK.

## Recommended First Pass

Start with the quick or wide plan. The full-factorial plan is useful for inventory, but it is too large for first-pass performance work because it mixes multiple causes in every run.

## Next Commands

\`\`\`bash
scheds/rust/scx_cake/bench/scx_cake_config_audit.sh --plan=wide
sudo scheds/rust/scx_cake/bench/scx_cake_scheduler_matrix.sh --cake-config-plan ${CONFIG_PLAN} --all
\`\`\`
EOF

echo "audit:   ${REPORT}"
echo "options: ${OPTIONS}"
echo "plan:    ${CONFIG_PLAN}"
echo "help:    ${HELP_FILE}"
