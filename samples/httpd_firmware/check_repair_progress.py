"""Read the WSL repair test outputs without printing API configuration."""
import json
from pathlib import Path

root = Path('/root/mango_0')
log = root / 'repair_tests/pipeline_tests.log'
if log.exists():
    for line in log.read_text().splitlines():
        if line.startswith(('Ran ', 'OK', 'FAILED')):
            print(line)
for path in sorted((root / 'repair_results/cedar').rglob('*_verdict.json')):
    print(path, path.read_text())
path = root / 'repair_results/cedar/intoverflow_mango.out'
if path.exists():
    print('LOG TAIL:', '\n'.join(path.read_text().splitlines()[-8:]))
