#!/usr/bin/env bash
# Usage: bash run_mango.sh LABEL VENV BINARY CATEGORY [category options...]
set -u
if [ "$#" -lt 4 ]; then
    printf 'Usage: bash run_mango.sh LABEL VENV BINARY CATEGORY [options...]\n' >&2
    exit 2
fi
label=$1
venv=$2
binary=$3
category=$4
shift 4
base=${MANGO_VM_ROOT:-"$HOME/mango-vm-test"}
out="$base/results/${label}_$(date -u +%Y%m%dT%H%M%SZ)_$$"
mkdir -p "$out"
unset PYTHONPATH PYTHONHOME
export PYTHONFAULTHANDLER=1 PYTHONUNBUFFERED=1
export TERM=dumb
ulimit -c 0
command=("$venv/bin/mango" "$binary" -c "$category" --results "$out/results" "$@")
printf '%q ' "${command[@]}" > "$out/command.txt"
printf '\n' >> "$out/command.txt"
date -u +%FT%TZ > "$out/start_utc.txt"
printf 'Running %s; logs: %s\n' "$label" "$out"
/usr/bin/time -v -o "$out/resources.txt" \
    timeout --signal=TERM --kill-after=30s "${MANGO_TIMEOUT:-20m}" \
    "${command[@]}" > "$out/console.log" 2>&1
status=$?
printf '%s\n' "$status" > "$out/exit_code.txt"
date -u +%FT%TZ > "$out/end_utc.txt"
printf '\nExit code: %s\nLogs: %s\n' "$status" "$out"
tail -n 25 "$out/console.log"
exit "$status"
