#!/usr/bin/env bash
set -euo pipefail
umask 022
OUT=/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/fresh_official
REPO=/root/mango_official
VENV=/root/myenv_mango_official
mkdir -p "$OUT"
exec > >(tee "$OUT/setup.log") 2>&1
trap 'status=$?; printf "%s\n" "$status" > "$OUT/setup_exit_code.txt"' EXIT
unset PYTHONPATH PYTHONHOME VIRTUAL_ENV
export PIP_DISABLE_PIP_VERSION_CHECK=1
export PYTHONUNBUFFERED=1
ulimit -c 0
if [ -e "$REPO" ] || [ -e "$VENV" ]; then
    printf 'Refusing to overwrite an existing official source or environment.\n'
    exit 97
fi
printf 'Cloning official source...\n'
git clone --depth 1 https://github.com/sefcom/operation-mango-public.git "$REPO"
git -C "$REPO" rev-parse HEAD | tee "$OUT/upstream_commit.txt"
git -C "$REPO" remote get-url origin > "$OUT/upstream_remote.txt"
cp "$REPO/README.md" "$OUT/upstream_README.md"
cp "$REPO/pyproject.toml" "$OUT/upstream_pyproject.toml"
cp "$REPO/docker/Dockerfile" "$OUT/upstream_Dockerfile"
printf 'Creating Python 3.11 virtual environment...\n'
/usr/bin/python3.11 -m venv "$VENV"
"$VENV/bin/python" --version
printf 'Installing official package and declared dependencies...\n'
cd "$REPO"
"$VENV/bin/python" -m pip install --upgrade pip setuptools wheel
"$VENV/bin/python" -m pip install --no-cache-dir -c "$OUT/constraints.txt" --report "$OUT/pip_install_report.json" .
"$VENV/bin/python" -m pip check | tee "$OUT/pip_check.txt"
"$VENV/bin/python" -m pip freeze --all > "$OUT/requirements.lock.txt"
"$VENV/bin/mango" --help > "$OUT/mango_help.txt"
"$VENV/bin/env_resolve" --help > "$OUT/env_resolve_help.txt"
"$VENV/bin/python" -c 'import json,sys,angr,pyvex,argument_resolver.analysis.mango as m; print(json.dumps(dict(python=sys.version,executable=sys.executable,prefix=sys.prefix,base_prefix=sys.base_prefix,angr=angr.__version__,pyvex=pyvex.__version__,mango_source=m.__file__),indent=2))' | tee "$OUT/environment.json"
printf 'Official environment installation finished.\n'
