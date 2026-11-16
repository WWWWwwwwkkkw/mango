import json
from pathlib import Path
import subprocess
import sys
import pyvex

root = Path(__file__).resolve().parent
from pyvex.enums import enums_to_ints
values = dict(enums_to_ints)
(root / 'native_constants.json').write_text(json.dumps(values))
results = []
for trial in range(1, 4):
    with (root / f'fake_native_{trial}.log').open('w') as log:
        p = subprocess.run([sys.executable, str(root / 'fake_native_probe.py')],
                           stdout=log, stderr=subprocess.STDOUT, timeout=55)
    row = dict(trial=trial, code=p.returncode)
    results.append(row)
    print(json.dumps(row), flush=True)
(root / 'fake_native_controls.json').write_text(json.dumps(results, indent=2))
