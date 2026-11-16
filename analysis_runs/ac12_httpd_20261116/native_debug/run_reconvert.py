import json
import os
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
results = []
for mode, script, options in [('reconvert', 'reconvert.py', []), ('debug_reconvert', 'reconvert.py', []), ('unowned', 'conversion_only.py', ['--unowned'])]:
    for trial in range(1, 4):
        env = dict(os.environ)
        if mode.startswith('debug'):
            env['PYTHONMALLOC'] = 'debug'
        with (root / f'{mode}_{trial}.log').open('w') as log:
            p = subprocess.run([sys.executable, str(root / script), *options], env=env,
                               stdout=log, stderr=subprocess.STDOUT, timeout=55)
        row = dict(mode=mode, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
        (root / 'reconvert_controls.json').write_text(json.dumps(results, indent=2))
