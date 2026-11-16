"""Read-only interpreter/package-path snapshot; never imports analysis libraries."""
import importlib.metadata as metadata
import importlib.util
import json
import os
from pathlib import Path
import shutil
import site
import sys
from collections import defaultdict

package_rows = []
by_name = defaultdict(list)
for distribution in metadata.distributions():
    name = distribution.metadata.get('Name', '')
    row = {'name': name, 'version': distribution.version, 'metadata_path': str(distribution._path)}
    package_rows.append(row)
    by_name[name.lower().replace('_', '-')].append(row)
focus_names = {'argument-resolver', 'angr', 'pyvex', 'cle', 'claripy', 'archinfo', 'cffi', 'pycparser', 'pip', 'setuptools', 'numpy'}
paths = []
for item in [*sys.path, *site.getsitepackages(), site.getusersitepackages()]:
    if item and item not in paths:
        paths.append(item)
startup = []
for item in paths:
    directory = Path(item)
    if directory.is_dir():
        for file in sorted(directory.glob('*.pth')):
            startup.append({'path': str(file), 'text': file.read_text(errors='replace')[:16000]})
specs = {}
for name in ['sitecustomize', 'usercustomize', 'argument_resolver', 'angr', 'pyvex', 'cffi', 'pycparser', 'pip']:
    try:
        spec = importlib.util.find_spec(name)
        specs[name] = None if spec is None else {'origin': spec.origin, 'locations': list(spec.submodule_search_locations or [])}
    except Exception as error:
        specs[name] = {'error': repr(error)}
configuration = Path(sys.prefix) / 'pyvenv.cfg'
record = {
    'version': sys.version, 'executable': sys.executable, 'executable_resolved': str(Path(sys.executable).resolve()),
    'prefix': sys.prefix, 'base_prefix': sys.base_prefix, 'is_venv': sys.prefix != sys.base_prefix,
    'pyvenv_cfg': configuration.read_text() if configuration.is_file() else None,
    'enable_user_site': site.ENABLE_USER_SITE, 'user_site': site.getusersitepackages(),
    'site_packages': site.getsitepackages(), 'sys_path': sys.path,
    'environment': {name: os.environ.get(name) for name in [
        'VIRTUAL_ENV', 'CONDA_PREFIX', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONUSERBASE',
        'PYTHONNOUSERSITE', 'LD_LIBRARY_PATH', 'LD_PRELOAD']},
    'command_resolution': {name: shutil.which(name) for name in ['python', 'python3', 'python3.11', 'python3.12', 'pip', 'pip3', 'mango', 'conda', 'pyenv', 'uv']},
    'package_count': len(package_rows),
    'focus_packages': [row for row in package_rows if row['name'].lower().replace('_', '-') in focus_names],
    'duplicate_distribution_metadata': {name: values for name, values in by_name.items() if len(values) > 1},
    'startup_pth_files': startup, 'module_locations': specs,
}
print(json.dumps(record, indent=2, ensure_ascii=False))
