"""Read-only Ubuntu interpreter/venv/package audit, written into this workspace."""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import time

root = Path(__file__).resolve().parent
output = root / ('python_environment_audit_' + datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ'))
output.mkdir()
snapshot = root / 'python_environment_snapshot.py'
print('OUTPUT ' + str(output), flush=True)
venvs = []
for start in ['/root', '/home', '/opt', '/usr/local']:
    if not Path(start).is_dir():
        continue
    for current, directories, files in os.walk(start):
        depth = len(Path(current).relative_to(start).parts)
        directories[:] = [name for name in directories if
            name not in {'.git', '.cache', 'node_modules', 'site-packages', 'dist-packages', 'squashfs-root', '__pycache__'}
            and not name.endswith('.extracted') and depth < 7]
        if 'pyvenv.cfg' in files:
            configuration = Path(current) / 'pyvenv.cfg'
            venvs.append({'root': current, 'configuration': configuration.read_text(errors='replace')})
            directories[:] = []
inventory = []
candidate_directories = [Path('/usr/bin'), Path('/usr/local/bin'), Path('/bin')]
candidate_directories += [path.parent for pattern in [
    '/root/.pyenv/versions/*/bin/python*', '/root/.local/share/uv/python/*/bin/python*',
    '/opt/*/bin/python*', '/root/miniconda*/bin/python*', '/root/anaconda*/bin/python*']
    for path in Path('/').glob(pattern.lstrip('/'))]
seen = set()
for directory in candidate_directories:
    if not directory.is_dir():
        continue
    for path in sorted(directory.glob('python*')):
        if not re.fullmatch(r'python(?:[23](?:\.\d+)?)?', path.name) or str(path) in seen:
            continue
        seen.add(str(path))
        inventory.append({'path': str(path), 'resolved': str(path.resolve()), 'symlink': path.is_symlink()})
(output / 'inventory.json').write_text(json.dumps({'interpreters': inventory, 'venvs': venvs,
    'venv_search': {'roots': ['/root', '/home', '/opt', '/usr/local'], 'max_depth': 7,
                    'excluded': ['caches', 'installed package trees', 'firmware extractions', 'node_modules', '.git']}}, indent=2))
commands = {
    'os_release': ['cat', '/etc/os-release'],
    'dpkg_python': ['dpkg-query', '-W', '-f=${binary:Package}\t${Version}\t${Status}\n', 'python3', 'python3.11', 'python3.12', 'python3-pip', 'python3-venv', 'python3.11-venv', 'python3.12-venv'],
    'apt_python_policy': ['apt-cache', 'policy', 'python3', 'python3.11', 'python3.12'],
    'dpkg_audit': ['dpkg', '--audit'],
}
for name, command in commands.items():
    result = subprocess.run(command, capture_output=True, text=True, timeout=40)
    (output / (name + '.txt')).write_text(result.stdout + result.stderr)
probes = {
    'system311': ['/usr/bin/python3.11', '-B', str(snapshot)],
    'system312': ['/usr/bin/python3.12', '-B', str(snapshot)],
    'old_myenv': ['/root/myenv/bin/python', '-B', str(snapshot)],
    'official_venv': ['/root/myenv_mango_official/bin/python', '-B', str(snapshot)],
    'interactive_login': ['bash', '-lic', 'python3 -B ' + str(snapshot)],
}
summary = {}
for name, command in probes.items():
    result = subprocess.run(command, capture_output=True, text=True, timeout=45)
    (output / (name + '.json')).write_text(result.stdout)
    (output / (name + '.stderr.txt')).write_text(result.stderr)
    summary[name] = {'exit_code': result.returncode}
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            summary[name].update(version=data['version'].splitlines()[0], executable=data['executable'],
                                  prefix=data['prefix'], is_venv=data['is_venv'], package_count=data['package_count'])
        except Exception as error:
            summary[name]['parse_error'] = repr(error)
    print(name, json.dumps(summary[name]), flush=True)
for name, executable in [('system311', '/usr/bin/python3.11'), ('system312', '/usr/bin/python3.12'),
                         ('old_myenv', '/root/myenv/bin/python'), ('official_venv', '/root/myenv_mango_official/bin/python')]:
    result = subprocess.run([executable, '-B', '-m', 'pip', 'check'], capture_output=True, text=True, timeout=45)
    (output / (name + '.pip_check.txt')).write_text(result.stdout + result.stderr)
    summary[name]['pip_check_exit'] = result.returncode
(output / 'summary.json').write_text(json.dumps(summary, indent=2))
print('VENV_ROOTS ' + json.dumps([item['root'] for item in venvs]), flush=True)
print('DONE ' + str(output), flush=True)
