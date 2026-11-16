#!/usr/bin/env bash
# Usage: bash runtime_suite.sh /absolute/path/to/uv-managed/python3.11 [repeats]
set -u
python_path=$1
repeats=${2:-20}
kit=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
base=${MANGO_VM_ROOT:-"$HOME/mango-vm-test"}
out="$base/results/runtime_$(date -u +%Y%m%dT%H%M%SZ)_$$"
mkdir -p "$out"
ulimit -c 0
failures=0
for ((trial=1; trial<=repeats; trial++)); do
    "$python_path" -I -S -B "$kit/runtime_repro.py" > "$out/trial_${trial}.log" 2>&1
    status=$?
    printf '%s\t%s\n' "$trial" "$status" >> "$out/exit_codes.tsv"
    printf 'Runtime test %s/%s: exit %s\n' "$trial" "$repeats" "$status"
    if [ "$status" -ne 0 ]; then
        failures=$((failures+1))
    fi
done
printf 'Failures: %s/%s\nLogs: %s\n' "$failures" "$repeats" "$out"
[ "$failures" -eq 0 ]
