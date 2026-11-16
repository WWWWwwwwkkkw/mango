#!/usr/bin/env bash
set -u
cd /root/intoverflow || exit 98
source /root/myenv/bin/activate
export PYTHONPATH=/root/intoverflow/package
export PYTHONUNBUFFERED=1
export TERM=dumb
export COLUMNS=120
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116
TARGET=/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd
date -u +%FT%TZ > "$OUT/start_utc.txt"
sha256sum "$TARGET" > "$OUT/target.sha256"
python -c 'import sys, argument_resolver.analysis.mango as m; print(sys.executable); print(m.__file__)' > "$OUT/implementation.txt"
/usr/bin/time -v -o "$OUT/resources.txt" mango "$TARGET" -c intoverflow --results "$OUT/results" > "$OUT/console.log" 2>&1
status=$?
printf '%s\n' "$status" > "$OUT/exit_code.txt"
date -u +%FT%TZ > "$OUT/end_utc.txt"
exit "$status"
