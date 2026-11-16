"""Repeat process-isolated FFI-boundary controls; do not modify myenv."""
import json
import os
from pathlib import Path
import subprocess
import sys
import time

root = Path(__file__).resolve().parent
out = root / 'boundary_repeats'
out.mkdir(exist_ok=True)
results = []
for trial in range(5):
    for mode, options in [('original', []), ('ctypes', ['--ctypes-lift']), ('profile', ['--profile'])]:
        start = time.monotonic()
        path = out / f'{mode}_{trial + 1}.log'
        with path.open('w') as log:
            process = subprocess.run(
                [sys.executable, str(root / 'pyvex_only_probe.py'), '--register-only', *options],
                stdout=log, stderr=subprocess.STDOUT, timeout=45,
            )
        result = dict(mode=mode, trial=trial + 1, code=process.returncode,
                      seconds=round(time.monotonic() - start, 3), log=str(path))
        results.append(result)
        print(json.dumps(result), flush=True)
        (out / 'results.json').write_text(json.dumps(results, indent=2))
