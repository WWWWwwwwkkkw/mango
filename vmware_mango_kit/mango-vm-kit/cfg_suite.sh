#!/usr/bin/env bash
# Usage: bash cfg_suite.sh LABEL VENV BINARY [repeats]
set -u
label=$1
venv=$2
binary=$3
repeats=${4:-3}
kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=${MANGO_VM_ROOT:-"$HOME/mango-vm-test"}
out="$base/results/${label}_cfg_$(date -u +%Y%m%dT%H%M%SZ)_$$"
mkdir -p "$out"
unset PYTHONPATH PYTHONHOME
export PYTHONFAULTHANDLER=1 PYTHONUNBUFFERED=1
ulimit -c 0
failures=0
for ((trial=1; trial<=repeats; trial++)); do
    /usr/bin/time -v -o "$out/trial_${trial}.resources.txt" \
        timeout --signal=TERM --kill-after=30s "${MANGO_TIMEOUT:-20m}" \
        "$venv/bin/python" "$kit/cfg_only.py" "$binary" > "$out/trial_${trial}.log" 2>&1
    status=$?
    printf '%s\t%s\n' "$trial" "$status" >> "$out/exit_codes.tsv"
    printf '%s CFG %s/%s: exit %s\n' "$label" "$trial" "$repeats" "$status"
    if [ "$status" -ne 0 ]; then failures=$((failures+1)); fi
done
printf 'Failures: %s/%s\nLogs: %s\n' "$failures" "$repeats" "$out"
[ "$failures" -eq 0 ]
