#!/usr/bin/env bash
# rt_displace_capture.sh — the §G93 RT-displacement trace (design council 2026-09-18).
#
# One system-wide perf record on the four sched tracepoints, with the samplers
# the parser joins on a shared clock. Runs as the user: tracefs event files
# readable (maintainer: chmod -R o+rX /sys/kernel/tracing), perf_event_paranoid -1,
# kernel.sched_schedstats=1. Output lands OUTSIDE the repo (~1.1 GB per 30 s).
#
#   rt_displace_capture.sh [SECS] [--dry]      default 30; --dry = 5 s desktop check
#
# The scheduler under test is whatever is attached; identity = the sorted
# struct_ops (name, tag) set from bpftool plus the loader log the maintainer tees.
set -u
SECS=${1:-30}; DRY=0; [[ "${2:-}" == "--dry" || "${1:-}" == "--dry" ]] && { DRY=1; SECS=5; }
OUT=${RT_OUT:-$HOME/Benchmarks/rt_displace_$(date +%Y%m%d_%H%M%S)}
mkdir -p "$OUT"
log() { echo "rt_displace: $*"; }

# --- preflight -----------------------------------------------------------------
cat /sys/kernel/tracing/events/sched/sched_switch/id >/dev/null 2>&1 || { log "tracefs event files not readable (maintainer: sudo chmod -R o+rX /sys/kernel/tracing)"; exit 2; }
[[ "$(cat /proc/sys/kernel/perf_event_paranoid)" -le 0 ]] || { log "perf_event_paranoid > 0"; exit 2; }
[[ "$(cat /proc/sys/kernel/sched_schedstats)" == "1" ]] || log "warn: sched_schedstats=0 (sudo -n sysctl -w kernel.sched_schedstats=1 for wait_max)"
GAME=$(pgrep -f 'Wow\.exe|WowB\.exe|Warframe\.x64\.exe' | head -1 || true)
[[ -n "$GAME" ]] || log "warn: no game process found; tracing whatever runs"

# --- identity and covariates ---------------------------------------------------
{ cat /sys/kernel/sched_ext/root/ops 2>/dev/null || echo native; } > "$OUT/scx_ops"
sudo -n /usr/bin/bpftool -j prog show 2>/dev/null | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: d=[]
for p in sorted((p.get("name",""),p.get("tag","")) for p in d if p.get("type")=="struct_ops"): print(*p)' > "$OUT/prog_tags" || true
git -C "$(dirname "$0")/../../../.." rev-parse HEAD > "$OUT/git_head" 2>/dev/null
python3 -c 'import time;print(time.time()-time.clock_gettime(time.CLOCK_MONOTONIC))' > "$OUT/clock_offset"
echo "$GAME" > "$OUT/game_pid"; uname -r > "$OUT/kernel"; date +%s.%N > "$OUT/t_start"

# --- writer CPU: not the game main thread's core, not CPU 4 (kwin), least busy ----
MAIN_CPU=-1
[[ -n "$GAME" ]] && MAIN_CPU=$(awk '{print $39}' /proc/$GAME/stat 2>/dev/null || echo -1)
NCPU=$(nproc); HALF=$((NCPU/2))
busy_pick() {
  local a b; a=$(grep '^cpu[0-9]' /proc/stat); sleep 1; b=$(grep '^cpu[0-9]' /proc/stat)
  paste <(echo "$a") <(echo "$b") | awk -v mc=$MAIN_CPU -v half=$HALF '{
    c=substr($1,4)+0; d=($13-$2)+($14-$3)+($15-$4)+($17-$6)+($18-$7);
    sib=(c<half)?c+half:c-half;
    if (c==mc||sib==mc||c==4||sib==4) next; print d, c }' | sort -n | head -1 | awk '{print $2}'
}
WCPU=$(busy_pick); WCPU=${WCPU:-$((NCPU-1))}
echo "$WCPU" > "$OUT/writer_cpu"

# --- samplers on the shared clock ------------------------------------------------
nvidia-smi --query-gpu=timestamp,utilization.gpu,clocks.gr,power.draw --format=csv,noheader -lms 1000 > "$OUT/gpu.csv" 2>/dev/null &
P_GPU=$!
( for _ in $(seq $((SECS+1))); do date +%s.%N; grep -E '^ *(46|80|97|135):' /proc/interrupts; grep -E '^ *(HI|TIMER|NET_RX|TASKLET|SCHED):' /proc/softirqs; sleep 1; done ) > "$OUT/irq.log" 2>/dev/null &
P_IRQ=$!
MOUSE=$(ls /dev/input/by-id/*event-mouse 2>/dev/null | head -1)
if [[ -n "$MOUSE" ]]; then
python3 - "$MOUSE" "$SECS" > "$OUT/mouse.log" 2>/dev/null <<'PY' &
import os,sys,time,select
fd=os.open(sys.argv[1],os.O_RDONLY|os.O_NONBLOCK); n=0; t0=time.time(); end=t0+float(sys.argv[2])+1
while time.time()<end:
    r,_,_=select.select([fd],[],[],max(0,t0+1-time.time()))
    if r:
        try: n+=len(os.read(fd,4096))//24
        except BlockingIOError: pass
    if time.time()>=t0+1: print(f"{time.time():.6f} {n}",flush=True); n=0; t0+=1
PY
P_MOUSE=$!
fi
# per-thread schedstat: game threads + the chain, at start and end
snap() {
  { [[ -n "$GAME" ]] && for t in /proc/$GAME/task/*; do echo "$(basename $t):$(tr ' ' '_' < $t/comm) $(cat $t/schedstat) $(awk '/se.nr_migrations|^nr_switches|nr_voluntary_switches|nr_involuntary_switches/{printf "%s ",$3}' $t/sched)"; done
    for p in $(ps -eo tid --no-headers -L); do c=$(cat /proc/$p/comm 2>/dev/null | tr ' ' '_'); case "$c" in kwin_wayland*|libinput*|pipewire*|wireplumber|data-loop*|irq/*|ksoftirqd/*|nvidia|nvidia-modeset*|nvidia-drm*|wineserver*|winedevice*|Xwayland*) echo "$p:$c $(cat /proc/$p/schedstat 2>/dev/null) $(awk '/se.nr_migrations|^nr_switches|nr_voluntary_switches|nr_involuntary_switches/{printf "%s ",$3}' /proc/$p/sched 2>/dev/null)";; esac; done
  } > "$OUT/sched_$1.txt"; date +%s.%N > "$OUT/ts_$1"; }
snap a
# MangoHud frame log through the control socket (abstract namespace), stamp the send
if [[ -n "$GAME" ]] && python3 - "$GAME" > "$OUT/mangohud_start" 2>/dev/null <<'PY'
import socket,sys,time
s=socket.socket(socket.AF_UNIX); s.connect("\0mangohud-"+sys.argv[1]); s.send(b":MangoHudControlVersion=1;:logging=1;"); print(f"{time.time():.6f}")
PY
then log "mangohud logging started"; else log "warn: MangoHud control socket not reachable (no frame log)"; fi

# --- the trace ----------------------------------------------------------------------
log "recording $SECS s on CPU $WCPU -> $OUT/perf.data (game pid ${GAME:-none}, main cpu $MAIN_CPU)"
taskset -c "$WCPU" perf record -a -k mono -m 4M -B -o "$OUT/perf.data" \
  -e sched:sched_switch -e sched:sched_waking -e sched:sched_wakeup -e sched:sched_migrate_task \
  -- sleep "$SECS" > "$OUT/perf.log" 2>&1
RC=$?
snap b
kill $P_GPU $P_IRQ ${P_MOUSE:-} 2>/dev/null; wait 2>/dev/null
date +%s.%N > "$OUT/t_end"
perf report -i "$OUT/perf.data" --stats 2>&1 | grep -iE 'lost|SAMPLE|TOTAL' | head -5 > "$OUT/perf_stats"
log "perf rc=$RC; $(du -h "$OUT/perf.data" | cut -f1); $(grep -i lost "$OUT/perf_stats" | head -1)"
[[ $DRY == 1 ]] && { log "dry run: check perf_stats (lost must be 0), mouse.log nonzero while moving, prog_tags non-empty"; }
echo "$OUT"
