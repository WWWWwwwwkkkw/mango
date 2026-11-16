import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
results = []
for mode, options in [('original', []), ('no_null', ['--no-null-check']), ('stmt_dispatch', ['--stmt-dispatch'])]:
    for trial in range(1, 4):
        with (root / f'dispatch_{mode}_{trial}.log').open('w') as log:
            p = subprocess.run([sys.executable, str(root / 'conversion_only.py'), *options],
                               stdout=log, stderr=subprocess.STDOUT, timeout=55)
        row = dict(mode=mode, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
        (root / 'dispatch_controls.json').write_text(json.dumps(results, indent=2))
