import json
from pathlib import Path
import subprocess
import sys
import tarfile

root = Path(__file__).resolve().parent
with tarfile.open(root / 'pyvex-9.2.94.tar.gz') as archive:
    upstream = archive.extractfile('pyvex-9.2.94/pyvex/stmt.py').read()
import pyvex
print('stmt.py equals upstream sdist:', upstream == (Path(pyvex.__file__).parent / 'stmt.py').read_bytes(), flush=True)
results = []
for mode in ['conversion', 'python-only', 'cffi-only']:
    for trial in range(1, 4):
        with (root / f'conversion_{mode}_{trial}.log').open('w') as log:
            p = subprocess.run([sys.executable, str(root / 'conversion_only.py'), '--' + mode],
                               stdout=log, stderr=subprocess.STDOUT, timeout=40)
        row = dict(mode=mode, trial=trial, code=p.returncode)
        results.append(row)
        print(json.dumps(row), flush=True)
(root / 'conversion_controls.json').write_text(json.dumps(results, indent=2))
