#!/usr/bin/env bash
set -u
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/native_debug
TOOLS="$OUT/toolroot"
export LD_LIBRARY_PATH="$TOOLS/usr/lib/x86_64-linux-gnu"
export DEBUGINFOD_URLS=
ulimit -c 0
timeout 90 "$TOOLS/usr/bin/gdb" -nx -nh --batch \
 -iex "set data-directory $TOOLS/usr/share/gdb" \
 -ex 'set pagination off' -ex 'set debuginfod enabled off' \
 -ex 'set breakpoint pending on' -ex 'break failure_exit' \
 -ex run -ex 'bt 35' -ex 'info locals' -ex 'info registers' \
 --args /root/myenv/bin/python "$OUT/pyvex_only_probe.py" --register-only --no-faulthandler \
 > "$OUT/gdb_vex_failure.log" 2>&1
status=$?
printf '%s\n' "$status" > "$OUT/gdb_vex_failure_exit.txt"
exit "$status"
