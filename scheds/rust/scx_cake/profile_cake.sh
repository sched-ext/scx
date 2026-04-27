#!/usr/bin/env bash

# Require root privileges
if [ "$EUID" -ne 0 ]; then
  echo "Please run this script with sudo: sudo ./profile_cake.sh"
  exit 1
fi

echo "Looking for active scx_cake BPF programs..."

# Names are clamped to 15 chars in BPF
PROG_NAMES=("cake_select_cpu" "cake_enqueue" "cake_dispatch" "cake_running" "cake_stopping")

declare -a FOUND_IDS
declare -a FOUND_NAMES

for name in "${PROG_NAMES[@]}"; do
    ID=$(bpftool prog show name $name --json 2>/dev/null | grep -o '"id": *[0-9]*' | head -n1 | grep -o '[0-9]*')
    if [ ! -z "$ID" ]; then
        FOUND_IDS+=("$ID")
        FOUND_NAMES+=("$name")
        echo "Found: $name (ID: $ID)"
    fi
done

if [ ${#FOUND_IDS[@]} -eq 0 ]; then
    echo "No scx_cake BPF programs found! Make sure the scheduler is actively running."
    exit 1
fi

# ==========================================
# GAME DETECTION LOGIC
# ==========================================
GAME_NAME="Desktop / Idle"
GAME_EXE=$(ps -eo pcpu,args --sort=-pcpu | awk 'tolower($0) ~ /\.exe/ && !/grep/ && !/wineboot/ && !/services/ && !/explorer/ && !/winedevice/ && !/wineserver/ {print $0; exit}')

if [ ! -z "$GAME_EXE" ]; then
    GAME_NAME=$(echo "$GAME_EXE" | awk -F'[/\\\\]' '{print $NF}' | awk '{print $1}')
else
    NATIVE_GAME=$(ps -eo pcpu,comm --sort=-pcpu | awk 'NR>1 && $2~/^(cs2|dota2|KovaaK|ArcRaiders|ffxiv)/ {print $2; exit}')
    if [ ! -z "$NATIVE_GAME" ]; then
        GAME_NAME="$NATIVE_GAME"
    fi
fi
# ==========================================

SAFE_NAME="${GAME_NAME// /_}"
SAFE_NAME="${SAFE_NAME//\//_}"
SAFE_NAME="${SAFE_NAME//.exe/}"
LOG_FILE="profile_${SAFE_NAME}_$(date +%s).log"

LOAD_AVG=$(cat /proc/loadavg | awk '{print $1" "$2" "$3}')

echo "--------------------------------------------------------" | tee -a "$LOG_FILE"
echo " ACTIVE CONTEXT: $GAME_NAME" | tee -a "$LOG_FILE"
echo " SYSTEM LOAD:    $LOAD_AVG" | tee -a "$LOG_FILE"
echo "--------------------------------------------------------" | tee -a "$LOG_FILE"
echo "Starting sequential profile (5 continuous seconds per function)... Play your game now!" | tee -a "$LOG_FILE"
echo "Results will stream below:" | tee -a "$LOG_FILE"
echo "--------------------------------------------------------" | tee -a "$LOG_FILE"

# Sequence the profiling to avoid bpftool multi-id syntax failures
for i in "${!FOUND_IDS[@]}"; do
    ID="${FOUND_IDS[$i]}"
    NAME="${FOUND_NAMES[$i]}"

    echo "" | tee -a "$LOG_FILE"
    echo "► Profiling $NAME for 5 seconds..." | tee -a "$LOG_FILE"
    bpftool prog profile id $ID duration 5 cycles instructions 2>&1 | tee -a "$LOG_FILE"
done

echo "" | tee -a "$LOG_FILE"
echo "--------------------------------------------------------" | tee -a "$LOG_FILE"
echo "Done! Full log safely captured at: $LOG_FILE"
