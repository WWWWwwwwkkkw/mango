import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
results = []
for mode, script, options in [('cffi_minimal', 'cffi_minimal.py', []), ('unowned_fixed', 'conversion_only.py', ['--unowned'])]:
    for trial in range(1, 6):
        with (root / f'{mode}_{trial}.log').open('w') as log:
            p = subprocess.run([sys.executable, str(root / script), *options],
                               stdout=log, stderr=subprocess.STDOUT, timeout=55)
        row = dict(mode=mode, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
        (root / 'minimal_controls.json').write_text(json.dumps(results, indent=2))
