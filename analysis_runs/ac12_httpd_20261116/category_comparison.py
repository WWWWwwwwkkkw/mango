"""Run every installed non-intoverflow category against the same firmware."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import sys
import time
import uuid

import angr
import argument_resolver.analysis.mango as mango
from argument_resolver.external_function.sink import VULN_TYPES

workspace = Path(__file__).resolve().parent
stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
output = workspace / f'category_comparison_{stamp}_{uuid.uuid4().hex[:6]}'
output.mkdir()
target = Path('/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd')
categories = list(VULN_TYPES)
timeout_seconds = 180
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
metadata = {
    'python': sys.version, 'executable': sys.executable, 'angr': angr.__version__,
    'mango_source': mango.__file__, 'target': str(target),
    'target_sha256': hashlib.sha256(target.read_bytes()).hexdigest(),
    'categories': categories, 'timeout_seconds_per_category': timeout_seconds,
    'cwd': '/root/mango_0', 'output': str(output),
}
(output / 'metadata.json').write_text(json.dumps(metadata, indent=2))
print('OUTPUT ' + str(output), flush=True)
env = dict(os.environ, PYTHONFAULTHANDLER='1', PYTHONUNBUFFERED='1', TERM='dumb', COLUMNS='120')
env.pop('PYTHONPATH', None)
records = []
for category in categories:
    category_dir = output / category
    category_dir.mkdir()
    command = ['/root/myenv/bin/mango', str(target), '-c', category,
               '--disable-progress', '--results', str(category_dir / 'results')]
    print('START ' + category, flush=True)
    started = time.monotonic()
    timed_out = False
    with (category_dir / 'console.log').open('w') as log:
        process = subprocess.Popen(
            ['/usr/bin/time', '-v', '-o', str(category_dir / 'resources.txt'), *command],
            cwd='/root/mango_0', env=env, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    content = (category_dir / 'console.log').read_text(errors='replace')
    segfault = process.returncode in (-11, 139) or 'Fatal Python error: Segmentation fault' in content
    stage = 'unknown'
    if 'cfg_fast.py' in content:
        stage = 'CFGFast'
    elif 'cfg_emulated.py' in content:
        stage = 'CFGEmulated'
    elif 'calling_convention' in content:
        stage = 'calling convention analysis'
    record = {
        'category': category, 'exit_code': process.returncode,
        'seconds': round(time.monotonic() - started, 3), 'timed_out': timed_out,
        'segfault': segfault, 'stage_from_trace': stage, 'command': command,
        'log': str(category_dir / 'console.log'),
        'result_files': [str(path.relative_to(category_dir)) for path in category_dir.rglob('*.json')],
    }
    records.append(record)
    (category_dir / 'exit.json').write_text(json.dumps(record, indent=2))
    (output / 'summary.json').write_text(json.dumps(records, indent=2))
    print(json.dumps(record), flush=True)
print('DONE ' + str(output), flush=True)
