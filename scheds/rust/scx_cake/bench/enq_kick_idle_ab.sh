#!/usr/bin/env bash
# enq_kick_idle_ab.sh — A/B harness for the SCX_ENQ_KICK_IDLE fold.
#
# Kernel for-7.2 (arighi aee94395c1f7) adds the SCX_ENQ_KICK_IDLE enq_flag:
# inserting into a local DSQ with that flag makes the kernel issue SCX_KICK_IDLE
# from local_dsq_post_enq(), folding cake's dsq_insert + scx_bpf_kick_cpu into a
# single kfunc crossing on idle wakes. cake resolves the flag bit from the booted
# kernel's BTF; if the kernel predates it the knob is a no-op (explicit kick).
#
# Two arms, IDENTICAL except the knob (so the A/B isolates the fold):
#   fold     SCX_CAKE_ENQ_KICK_IDLE=1   insert carries the idle-kick   (1 kfunc)
#   explicit knob unset                 insert + scx_bpf_kick_cpu      (2 kfuncs)
#
# GATE (make-or-break): on the patched 7.1 kernel the `fold` arm MUST print at
# startup:  "SCX_ENQ_KICK_IDLE on: ... flag=0x..."
# If you instead see "booted kernel lacks SCX_ENQ_KICK_IDLE", the patch is NOT in
# the running kernel and any A/B numbers are meaningless — stop and fix the boot.
#
# Usage:
#   sudo is invoked internally; run as your normal user.
#   ./enq_kick_idle_ab.sh fold      [extra scx_cake args...]
#   ./enq_kick_idle_ab.sh explicit  [extra scx_cake args...]
# Both arms must be passed the SAME extra args. cake runs in the foreground;
# Ctrl-C to stop, then swap arms. Measure enqueue-ns + kick counts with:
#   sudo cake-bpfstats ftrace-start   # before the game scene
#   ...play the identical scene...
#   sudo cake-bpfstats ftrace-dump | grep -E 'scx_bpf_kick_cpu|cake_enqueue'
#   sudo cake-bpfstats ftrace-stop
# Expect the `fold` arm to show fewer scx_bpf_kick_cpu hits (idle kicks moved
# into the kernel) and lower aggregate enqueue-path kfunc time.
set -euo pipefail

ARM="${1:-}"
shift || true
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../../.." && pwd)"
BIN="$REPO/target/release/scx_cake"
CAKE_ARGS=( "$@" )   # both arms share these verbatim; knob is the only delta

case "$ARM" in
  fold)     KNOB=( SCX_CAKE_ENQ_KICK_IDLE=1 ) ;;
  explicit) KNOB=() ;;
  *) echo "usage: $0 {fold|explicit} [extra scx_cake args...]" >&2; exit 2 ;;
esac

[ -x "$BIN" ] || {
  echo "missing $BIN — build it: cargo build --release --package scx_cake" >&2
  exit 1
}

echo "==> arm=$ARM  knob=${KNOB[*]:-none}  args=${CAKE_ARGS[*]:-<baked release config>}"
if [ "$ARM" = fold ]; then
  echo "==> WATCH startup log: require 'SCX_ENQ_KICK_IDLE on: ... flag=0x...'"
  echo "==> if it says 'booted kernel lacks SCX_ENQ_KICK_IDLE' -> patch not live, ABORT."
fi
# sudo scrubs the environment, so the knob is set INSIDE the sudo command line
# (sudo VAR=val cmd) rather than as a shell prefix that would never reach cake.
exec sudo "${KNOB[@]}" "$BIN" "${CAKE_ARGS[@]}"
