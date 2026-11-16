#!/usr/bin/env bash
set -u
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116
TOOLS="$OUT/native_debug/toolroot"
export VALGRIND_LIB="$TOOLS/usr/libexec/valgrind"
export PYTHONMALLOC=malloc
export PYTHONUNBUFFERED=1
MODE=${1:-cfg}
SCRIPT="$OUT/diagnose_cfg.py"
ARGS=()
if [ "$MODE" = readonly ]; then
  SCRIPT="$OUT/native_debug/pyvex_only_probe.py"
  ARGS=(--readonly)
fi
printf 'running\n' > "$OUT/native_debug/valgrind_${MODE}_exit.txt"
ulimit -c 0
timeout 360 "$TOOLS/usr/bin/valgrind" \
  --tool=memcheck --leak-check=no --undef-value-errors=no \
  --num-callers=30 \
  --error-exitcode=99 --exit-on-first-error=yes \
  --log-file="$OUT/native_debug/valgrind_${MODE}_memory.log" \
  /root/myenv/bin/python "$SCRIPT" "${ARGS[@]}" \
  > "$OUT/native_debug/valgrind_${MODE}_console.log" 2>&1
status=$?
printf '%s\n' "$status" > "$OUT/native_debug/valgrind_${MODE}_exit.txt"
exit "$status"
