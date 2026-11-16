#!/usr/bin/env bash
set -u
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116
TOOLS="$OUT/native_debug/toolroot"
export LD_LIBRARY_PATH="$TOOLS/usr/lib/x86_64-linux-gnu"
export DEBUGINFOD_URLS=
MODE=${1:-baseline}
if [ "$MODE" = debug ]; then export PYTHONMALLOC=debug; fi
ulimit -c 0
timeout 180 "$TOOLS/usr/bin/gdb" -nx -nh --batch \
  -iex "set data-directory $TOOLS/usr/share/gdb" \
  -ex 'set pagination off' \
  -ex 'set debuginfod enabled off' \
  -ex 'set confirm off' \
  -ex 'handle SIGSEGV stop print nopass' \
  -ex run \
  -ex 'bt 45' \
  -ex 'thread apply all bt 12' \
  -ex 'info registers' \
  -ex 'x/16i $pc-24' \
  -ex 'info sharedlibrary' \
  --args /root/myenv/bin/python "$OUT/diagnose_cfg.py" \
  > "$OUT/native_debug/gdb_${MODE}.log" 2>&1
status=$?
printf '%s\n' "$status" > "$OUT/native_debug/gdb_${MODE}_exit.txt"
exit "$status"
