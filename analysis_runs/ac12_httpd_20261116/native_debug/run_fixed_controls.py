import json
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parent
results = []
for mode, options in [('mips', []), ('mips_no_gc', ['--no-gc']), ('x86', ['--x86'])]:
    for trial in range(1, 4):
        with (root / f'fixed_{mode}_{trial}.log').open('w') as log:
            p = subprocess.run([sys.executable, str(root / 'fixed_block.py'), *options],
                               stdout=log, stderr=subprocess.STDOUT, timeout=55)
        row = dict(mode=mode, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
        (root / 'fixed_controls.json').write_text(json.dumps(results, indent=2))
