#!/usr/bin/env bash
set -euo pipefail
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/fresh_extended
BASE=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/fresh_official
VENV=/root/myenv_mango_extended
mkdir -p "$OUT"
exec > >(tee "$OUT/setup.log") 2>&1
trap 'status=$?; printf "%s\n" "$status" > "$OUT/setup_exit_code.txt"' EXIT
unset PYTHONPATH PYTHONHOME VIRTUAL_ENV
export PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONUNBUFFERED=1
ulimit -c 0
if [ -e "$VENV" ]; then
    printf 'Refusing to overwrite existing environment: %s\n' "$VENV"
    exit 97
fi
/usr/bin/python3.11 -m venv "$VENV"
/usr/bin/python3.12 -B -c 'from pathlib import Path; import sys; lines=Path(sys.argv[1]).read_text().splitlines(); Path(sys.argv[2]).write_text("\n".join(line for line in lines if not line.lower().replace("_", "-").startswith("argument-resolver "))+"\n")' "$BASE/requirements.lock.txt" "$OUT/dependencies.lock.txt"
"$VENV/bin/python" -m pip install --no-deps -r "$OUT/dependencies.lock.txt" --report "$OUT/dependency_install_report.json"
"$VENV/bin/python" -m pip install --no-deps --no-build-isolation --report "$OUT/extension_install_report.json" /root/mango_0
"$VENV/bin/python" -m pip check | tee "$OUT/pip_check.txt"
"$VENV/bin/python" -m pip freeze --all > "$OUT/requirements.lock.txt"
"$VENV/bin/mango" --help > "$OUT/mango_help.txt"
"$VENV/bin/python" -c 'import json,sys,angr,pyvex,cffi,pycparser,argument_resolver.analysis.mango as m; print(json.dumps(dict(python=sys.version,executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,angr=angr.__version__,pyvex=pyvex.__version__,cffi=cffi.__version__,pycparser=pycparser.__version__,mango_source=m.__file__),indent=2))' | tee "$OUT/environment.json"
printf 'Extended environment installed with official-baseline dependency versions.\n'
