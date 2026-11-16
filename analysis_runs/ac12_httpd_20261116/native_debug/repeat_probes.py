"""Repeat controls to distinguish a causal setting from a heap-layout coincidence."""
from pathlib import Path
import json
import os
import subprocess
import sys

root = Path(__file__).resolve().parent
output = root / os.environ.get('MANGO_PROBE_LABEL', '')
output.mkdir(parents=True, exist_ok=True)
results = []
for mode, args in [('baseline', []), ('register_only', ['--register-only']), ('readonly', ['--readonly'])]:
    for trial in range(1, 4):
        completed = subprocess.run([sys.executable, str(root / 'pyvex_only_probe.py'), *args], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        (output / f'repeat_{mode}_{trial}.log').write_bytes(completed.stdout)
        result = {'mode': mode, 'trial': trial, 'exit_code': completed.returncode}
        results.append(result)
        print(json.dumps(result), flush=True)
(output / 'repeat_results.json').write_text(json.dumps(results, indent=2))
