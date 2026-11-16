#!/usr/bin/env bash
set -euo pipefail
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/fresh_official
VENV=/root/myenv_mango_official
exec > >(tee "$OUT/configure.log") 2>&1
trap 'status=$?; printf "%s\n" "$status" > "$OUT/configure_exit_code.txt"' EXIT
unset PYTHONPATH PYTHONHOME VIRTUAL_ENV
export PIP_DISABLE_PIP_VERSION_CHECK=1 PYTHONUNBUFFERED=1
ulimit -c 0
cp "$OUT/requirements.lock.txt" "$OUT/requirements.initial.lock.txt"
"$VENV/bin/python" -m pip install --no-cache-dir -c "$OUT/constraints.txt" pycparser
"$VENV/bin/python" -m pip check | tee "$OUT/pip_check.txt"
"$VENV/bin/python" -m pip freeze --all > "$OUT/requirements.lock.txt"
"$VENV/bin/mango" --help > "$OUT/mango_help.txt"
"$VENV/bin/env_resolve" --help > "$OUT/env_resolve_help.txt"
"$VENV/bin/python" -c 'import json,sys,angr,pyvex,cffi,pycparser,argument_resolver.analysis.mango as m; print(json.dumps(dict(python=sys.version,executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,angr=angr.__version__,pyvex=pyvex.__version__,cffi=cffi.__version__,pycparser=pycparser.__version__,mango_source=m.__file__),indent=2))' | tee "$OUT/environment.json"
printf 'New environment configured and CLI import checks passed.\n'
