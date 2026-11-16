cat /etc/os-release
uname -m
python3 --version
free -h
df -h "$HOME"

sudo apt-get update
sudo apt-get install -y \
  curl ca-certificates git build-essential pkg-config \
  libffi-dev libssl-dev libgomp1 graphviz \
  file unzip xz-utils time


curl -LsSf https://astral.sh/uv/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"
uv --version


export MANGO_VM_ROOT="$HOME/mango-vm-test"
mkdir -p "$MANGO_VM_ROOT"
unzip "$HOME/Downloads/mango-vm-kit.zip" -d "$MANGO_VM_ROOT"
export MANGO_KIT="$MANGO_VM_ROOT/mango-vm-kit"
mkdir -p "$MANGO_VM_ROOT/results"

(cd "$MANGO_KIT" && sha256sum -c SHA256SUMS)
file "$MANGO_KIT/httpd"
sha256sum "$MANGO_KIT/httpd"


uv python install 3.11
uv python list --only-installed
export MANGO_PY311="$(uv python find --managed-python 3.11)"

printf 'uv Python: %s\n' "$MANGO_PY311"
"$MANGO_PY311" -VV
"$MANGO_PY311" -I -S -c 'import sys; print("executable:",sys.executable); print("base_prefix:",sys.base_prefix)'
python3 --version

uv --version > "$MANGO_VM_ROOT/results/uv-version.txt"
"$MANGO_PY311" -VV > "$MANGO_VM_ROOT/results/python-version.txt" 2>&1


cat > "$MANGO_VM_ROOT/settings.sh" <<'EOF'
export PATH="$HOME/.local/bin:$PATH"
export MANGO_VM_ROOT="${MANGO_VM_ROOT:-$HOME/mango-vm-test}"
export MANGO_KIT="$MANGO_VM_ROOT/mango-vm-kit"
export MANGO_OFF_SRC="$MANGO_VM_ROOT/operation-mango-public"
export MANGO_EXT_SRC="$MANGO_VM_ROOT/mango_0"
export MANGO_OFF_ENV="$MANGO_VM_ROOT/.venv-official"
export MANGO_EXT_ENV="$MANGO_VM_ROOT/.venv-extended"
export MANGO_TARGET="$MANGO_KIT/httpd"
export MANGO_PY311="$(uv python find --managed-python 3.11)"
unset PYTHONPATH PYTHONHOME
EOF

source "$MANGO_VM_ROOT/settings.sh"


export MANGO_VM_ROOT="$HOME/mango-vm-test"
source "$MANGO_VM_ROOT/settings.sh"


bash "$MANGO_KIT/runtime_suite.sh" "$MANGO_PY311" 20


git clone https://github.com/sefcom/operation-mango-public.git "$MANGO_OFF_SRC"
git -C "$MANGO_OFF_SRC" checkout --detach 85034001d7ce365de5c3520e486ac5ed7adf0bc3
git -C "$MANGO_OFF_SRC" rev-parse HEAD \
  > "$MANGO_VM_ROOT/results/official-commit.txt"

uv venv --python "$MANGO_PY311" "$MANGO_OFF_ENV"

uv pip install --python "$MANGO_OFF_ENV/bin/python" \
  -r "$MANGO_KIT/requirements-baseline.lock"

uv pip install --python "$MANGO_OFF_ENV/bin/python" \
  --no-deps --no-build-isolation "$MANGO_OFF_SRC"

uv pip check --python "$MANGO_OFF_ENV/bin/python"
"$MANGO_OFF_ENV/bin/python" -X faulthandler -m pip check
uv pip freeze --python "$MANGO_OFF_ENV/bin/python" \
  > "$MANGO_VM_ROOT/results/official-freeze.txt"

"$MANGO_OFF_ENV/bin/mango" --help
"$MANGO_OFF_ENV/bin/env_resolve" --help
"$MANGO_OFF_ENV/bin/python" -c 'import sys,angr,pyvex,pycparser; import argument_resolver.analysis.mango as m; print(sys.executable); print(angr.__version__,pyvex.__version__,pycparser.__version__); print(m.__file__)'


bash "$MANGO_KIT/run_mango.sh" \
  official_simple "$MANGO_OFF_ENV" \
  "$MANGO_OFF_SRC/package/tests/binaries/simple/program" \
  cmdi --disable-progress


bash "$MANGO_KIT/cfg_suite.sh" \
  official "$MANGO_OFF_ENV" "$MANGO_TARGET" 3


bash "$MANGO_KIT/run_mango.sh" \
  official_cmdi "$MANGO_OFF_ENV" "$MANGO_TARGET" \
  cmdi --disable-progress


export MANGO_VM_ROOT="$HOME/mango-vm-test"
source "$MANGO_VM_ROOT/settings.sh"
find "$MANGO_VM_ROOT/results" -name console.log -print


export MANGO_TIMEOUT=40m


tar -xzf "$MANGO_KIT/mango_0_source.tar.gz" -C "$MANGO_VM_ROOT"
test -f "$MANGO_EXT_SRC/pyproject.toml"

uv venv --python "$MANGO_PY311" "$MANGO_EXT_ENV"

uv pip install --python "$MANGO_EXT_ENV/bin/python" \
  -r "$MANGO_KIT/requirements-baseline.lock"

uv pip install --python "$MANGO_EXT_ENV/bin/python" \
  --no-deps --no-build-isolation "$MANGO_EXT_SRC"

uv pip check --python "$MANGO_EXT_ENV/bin/python"
"$MANGO_EXT_ENV/bin/python" -X faulthandler -m pip check
uv pip freeze --python "$MANGO_EXT_ENV/bin/python" \
  > "$MANGO_VM_ROOT/results/extended-freeze.txt"

"$MANGO_EXT_ENV/bin/mango" --help
"$MANGO_EXT_ENV/bin/python" -c 'import sys,angr,pyvex,pycparser; import argument_resolver.analysis.mango as m; print(sys.executable); print(angr.__version__,pyvex.__version__,pycparser.__version__); print(m.__file__)'


bash "$MANGO_KIT/cfg_suite.sh" \
  extended "$MANGO_EXT_ENV" "$MANGO_TARGET" 3

bash "$MANGO_KIT/run_mango.sh" \
  extended_cmdi "$MANGO_EXT_ENV" "$MANGO_TARGET" \
  cmdi --disable-progress

bash "$MANGO_KIT/run_mango.sh" \
  extended_intoverflow "$MANGO_EXT_ENV" "$MANGO_TARGET" \
  intoverflow --skip-llm


for trial in 1 2; do
  bash "$MANGO_KIT/run_mango.sh" \
    "official_cmdi_repeat_$trial" "$MANGO_OFF_ENV" "$MANGO_TARGET" \
    cmdi --disable-progress

  bash "$MANGO_KIT/run_mango.sh" \
    "extended_cmdi_repeat_$trial" "$MANGO_EXT_ENV" "$MANGO_TARGET" \
    cmdi --disable-progress
done


bash "$MANGO_KIT/run_mango.sh" \
  extended_intoverflow_repeat "$MANGO_EXT_ENV" "$MANGO_TARGET" \
  intoverflow --skip-llm


"$MANGO_PY311" -I -S "$MANGO_KIT/summarize_results.py" \
  "$MANGO_VM_ROOT/results"

find "$MANGO_VM_ROOT/results" -name exit_code.txt -print -exec cat {} \;

tar -czf "$HOME/mango-vm-results-$(date +%Y%m%d-%H%M%S).tar.gz" \
  -C "$MANGO_VM_ROOT" results settings.sh


sudo dmesg -T | tail -n 100


source "$MANGO_OFF_ENV/bin/activate"
which python
which mango
python --version
deactivate

source "$MANGO_EXT_ENV/bin/activate"
which python
which mango
python --version
deactivate
