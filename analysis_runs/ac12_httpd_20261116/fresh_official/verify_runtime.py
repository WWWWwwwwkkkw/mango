"""Check the earlier standalone Python reproducer in the newly created venv."""
import json
from pathlib import Path
import resource
import subprocess
import time

root = Path(__file__).resolve().parent
probe = root.parent / 'native_debug/python_runtime_repro.py'
executable = '/root/myenv_mango_official/bin/python'
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
records = []
for trial in range(1, 6):
    started = time.monotonic()
    with (root / f'runtime_{trial}.log').open('w') as log:
        process = subprocess.run([executable, '-I', '-B', str(probe)], stdout=log, stderr=subprocess.STDOUT, timeout=40)
    row = dict(trial=trial, exit_code=process.returncode, seconds=round(time.monotonic()-started, 3))
    records.append(row)
    print(json.dumps(row), flush=True)
    (root / 'runtime_verification.json').write_text(json.dumps(records, indent=2))
