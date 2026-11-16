import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
if sys.platform == 'win32':
    executables = [sys.executable, str(Path(os.environ['USERPROFILE']) / '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe')]
else:
    executables = [sys.executable, '/usr/bin/python3.12']
results = []
for number, executable in enumerate(executables):
    version = subprocess.check_output([executable, '--version'], text=True).strip()
    for trial in range(1, 4):
        with (root / f'cross_{sys.platform}_{number}_{trial}.log').open('w') as log:
            p = subprocess.run([executable, '-B', str(root / 'fake_native_probe.py'), '--pure-python', '--local-source'],
                               stdout=log, stderr=subprocess.STDOUT, timeout=55)
        row = dict(executable=executable, version=version, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
        (root / f'cross_runtime_{sys.platform}.json').write_text(json.dumps(results, indent=2))
