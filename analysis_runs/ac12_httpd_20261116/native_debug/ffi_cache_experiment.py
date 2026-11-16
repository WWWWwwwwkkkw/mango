"""ABA test of PyVEX's pickled private CFFI parser cache, preserving all originals."""
from pathlib import Path
import json
import os
import subprocess
import sys
import uuid

root = Path(__file__).resolve().parent
out = root / ('ffi_cache_experiment_' + uuid.uuid4().hex[:8])
out.mkdir()
results = []
for trial in range(1, 4):
    tempdir = out / f'tmp_{trial}'
    tempdir.mkdir()
    env = dict(os.environ, TMPDIR=str(tempdir))
    for stage in ['miss', 'hit', 'miss_again']:
        caches = list(tempdir.glob('pyvex_ffi_parser_cache.*'))
        if stage == 'miss_again':
            for cache in caches:
                cache.rename(cache.with_name(cache.name + '.preserved'))
        before = [str(path.name) for path in tempdir.glob('pyvex_ffi_parser_cache.*') if not path.name.endswith('.preserved')]
        completed = subprocess.run([sys.executable, str(root / 'pyvex_only_probe.py'), '--register-only'], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=30)
        (out / f'trial_{trial}_{stage}.log').write_bytes(completed.stdout)
        result = {'trial': trial, 'stage': stage, 'cache_before': before, 'exit_code': completed.returncode}
        results.append(result)
        print(json.dumps(result), flush=True)
(out / 'results.json').write_text(json.dumps(results, indent=2))
(root / 'ffi_cache_experiment_latest.txt').write_text(str(out))
