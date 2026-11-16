import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
results = []
for trial in range(1, 6):
    with (root / f'standalone_{sys.platform}_{trial}.log').open('w') as log:
        p = subprocess.run([sys.executable, '-I', '-B', str(root / 'python_runtime_repro.py')],
                           stdout=log, stderr=subprocess.STDOUT, timeout=55)
    row = dict(trial=trial, code=p.returncode, executable=sys.executable)
    results.append(row)
    print(json.dumps(row), flush=True)
    (root / f'standalone_{sys.platform}.json').write_text(json.dumps(results, indent=2))
