import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
results = []
for mode, executable in [('python311', sys.executable), ('python312', '/usr/bin/python3.12')]:
    for trial in range(1, 4):
        with (root / f'pure_python_{mode}_{trial}.log').open('w') as log:
            p = subprocess.run([executable, str(root / 'fake_native_probe.py'), '--pure-python'],
                               stdout=log, stderr=subprocess.STDOUT, timeout=55)
        row = dict(mode=mode, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
        (root / 'pure_python_controls.json').write_text(json.dumps(results, indent=2))
