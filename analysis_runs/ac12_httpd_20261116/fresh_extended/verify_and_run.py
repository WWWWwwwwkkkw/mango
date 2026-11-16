"""Two isolated runs of the unmodified extension using the official dependency lock."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

root = Path(__file__).resolve().parent
venv = Path('/root/myenv_mango_extended')
target = Path('/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd')
source = Path('/root/mango_0')
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
env = dict(os.environ, PYTHONFAULTHANDLER='1', PYTHONUNBUFFERED='1', TERM='dumb', COLUMNS='120')
for key in ['PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV']:
    env.pop(key, None)

def lock_rows(file):
    return sorted(line.strip().lower().replace('_', '-') for line in file.read_text().splitlines()
                  if line.strip() and not line.lower().replace('_', '-').startswith('argument-resolver '))

baseline = lock_rows(root.parent / 'fresh_official/requirements.lock.txt')
current = lock_rows(root / 'requirements.lock.txt')
parity = {'identical_dependency_versions': baseline == current,
          'only_official': sorted(set(baseline) - set(current)),
          'only_extended': sorted(set(current) - set(baseline))}
(root / 'dependency_comparison.json').write_text(json.dumps(parity, indent=2))
assert parity['identical_dependency_versions'], parity
help_text = (root / 'mango_help.txt').read_text()
assert 'intoverflow' in help_text and '--skip-llm' in help_text
hashes = {}
installed = venv / 'lib/python3.11/site-packages'
for relative in ['analysis/mango.py', 'analysis/integer_overflow.py', 'utils/integer_overflow.py', 'utils/integer_overflow_detection.py']:
    path = Path('argument_resolver') / relative
    originals = source / 'package' / path
    copy = installed / path
    left, right = hashlib.sha256(originals.read_bytes()).hexdigest(), hashlib.sha256(copy.read_bytes()).hexdigest()
    hashes[relative] = {'source_sha256': left, 'installed_sha256': right, 'match': left == right}
    assert left == right
(root / 'source_hashes.json').write_text(json.dumps(hashes, indent=2))
metadata = {'target': str(target), 'target_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
            'environment': str(venv), 'source': str(source), 'categories': ['cmdi', 'intoverflow'],
            'intoverflow_llm': 'disabled by explicit user choice', 'per_case_timeout_seconds': 900,
            'dependency_parity': parity['identical_dependency_versions']}
(root / 'test_metadata.json').write_text(json.dumps(metadata, indent=2))
records = []
for category in ['cmdi', 'intoverflow']:
    output = root / category
    output.mkdir(exist_ok=False)
    command = [str(venv / 'bin/mango'), str(target), '-c', category, '--results', str(output / 'results')]
    if category == 'intoverflow':
        command.append('--skip-llm')
    else:
        command.append('--disable-progress')
    print('START ' + category, flush=True)
    started = time.monotonic()
    timed_out = False
    with (output / 'console.log').open('w') as log:
        process = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(output / 'resources.txt'), *command],
                                   cwd=source, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=900)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    content = (output / 'console.log').read_text(errors='replace')
    row = {'category': category, 'command': command, 'exit_code': process.returncode,
           'seconds': round(time.monotonic() - started, 3), 'timed_out': timed_out,
           'segfault': process.returncode in [-11, 139] or 'Fatal Python error: Segmentation fault' in content,
           'result_json_files': [str(path.relative_to(output)) for path in output.rglob('*results.json')]}
    (output / 'exit.json').write_text(json.dumps(row, indent=2))
    records.append(row)
    (root / 'test_summary.json').write_text(json.dumps(records, indent=2))
    print(json.dumps(row), flush=True)
print('DONE EXTENDED COMPARISON', flush=True)
