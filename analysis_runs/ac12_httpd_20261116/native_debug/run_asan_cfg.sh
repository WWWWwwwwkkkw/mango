#!/usr/bin/env bash
set -u
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/native_debug
export LD_PRELOAD=/usr/lib/gcc/x86_64-linux-gnu/13/libasan.so
export ASAN_OPTIONS=detect_leaks=0:abort_on_error=1
export PYTHONMALLOC=malloc
export PYTHONUNBUFFERED=1
export PYTHONPATH="$OUT/asan_overlay"
ulimit -c 0
timeout 180 /root/myenv/bin/python "$OUT/cfg_minimal.py" > "$OUT/asan_full_cfg.log" 2>&1
status=$?
printf '%s\n' "$status" > "$OUT/asan_full_cfg_exit.txt"
exit "$status"
