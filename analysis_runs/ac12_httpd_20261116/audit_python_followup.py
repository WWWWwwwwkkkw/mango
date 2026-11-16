"""Complete read-only environment audit and capture unexpected pip crash."""
import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
snapshot = Path(__file__).resolve().parent / 'python_environment_snapshot.py'
inventory = json.loads((root / 'inventory.json').read_text())
records = []
for item in inventory['venvs']:
    if item['root'] in ['/root/myenv', '/root/myenv_mango_official']:
        continue
    executable = str(Path(item['root']) / 'bin/python')
    label = 'extra_' + str(len(records) + 1)
    process = subprocess.run([executable, '-B', str(snapshot)], capture_output=True, text=True, timeout=40)
    (root / (label + '.json')).write_text(process.stdout)
    (root / (label + '.stderr.txt')).write_text(process.stderr)
    row = {'root': item['root'], 'snapshot_exit': process.returncode, 'snapshot_file': label + '.json'}
    if process.returncode == 0:
        data = json.loads(process.stdout)
        row.update(version=data['version'], packages=data['package_count'])
    check = subprocess.run([executable, '-B', '-X', 'faulthandler', '-m', 'pip', 'check'], capture_output=True, text=True, timeout=40)
    (root / (label + '.pip_check.txt')).write_text(check.stdout + check.stderr)
    row['pip_check_exit'] = check.returncode
    records.append(row)
    print(json.dumps(row), flush=True)
repeat = []
for trial in range(1, 3):
    process = subprocess.run(['/root/myenv_mango_official/bin/python', '-B', '-X', 'faulthandler', '-m', 'pip', 'check'], capture_output=True, text=True, timeout=40)
    (root / f'official_pip_repeat_{trial}.txt').write_text(process.stdout + process.stderr)
    repeat.append({'trial': trial, 'exit_code': process.returncode})
    print('official_pip_repeat', trial, process.returncode, flush=True)
command = ['dpkg', '-V', 'python3.11-minimal', 'libpython3.11-minimal', 'libpython3.11-stdlib',
           'python3.12-minimal', 'libpython3.12-minimal', 'libpython3.12-stdlib']
process = subprocess.run(command, capture_output=True, text=True, timeout=45)
(root / 'dpkg_verify_python.txt').write_text(process.stdout + process.stderr)
(root / 'followup_summary.json').write_text(json.dumps({'extra_venvs': records, 'official_pip_repeats': repeat,
    'dpkg_verify_python': {'command': command, 'exit_code': process.returncode, 'output_empty': not bool(process.stdout or process.stderr)}}, indent=2))
print('dpkg_verify_python', process.returncode, repr(process.stdout + process.stderr), flush=True)
