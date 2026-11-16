"""Correct static-only invocation: intoverflow rejects --disable-progress."""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

root = Path(__file__).resolve().parent
output = root / 'intoverflow_static'
output.mkdir(exist_ok=False)
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
command = ['/root/myenv_mango_extended/bin/mango', target, '-c', 'intoverflow',
           '--results', str(output / 'results'), '--skip-llm']
env = dict(os.environ, PYTHONFAULTHANDLER='1', PYTHONUNBUFFERED='1', TERM='dumb', COLUMNS='120')
for key in ['PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV']:
    env.pop(key, None)
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
started = time.monotonic()
timed_out = False
print('START intoverflow static, corrected arguments', flush=True)
with (output / 'console.log').open('w') as log:
    process = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(output / 'resources.txt'), *command],
                               cwd='/root/mango_0', env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        process.wait(timeout=900)
    except subprocess.TimeoutExpired:
        timed_out = True
        os.killpg(process.pid, signal.SIGTERM)
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
content = (output / 'console.log').read_text(errors='replace')
record = {'category': 'intoverflow', 'command': command, 'exit_code': process.returncode,
          'seconds': round(time.monotonic()-started, 3), 'timed_out': timed_out,
          'segfault': process.returncode in [-11, 139] or 'Fatal Python error: Segmentation fault' in content,
          'result_json_files': [str(path.relative_to(output)) for path in output.rglob('*results.json')]}
(output / 'exit.json').write_text(json.dumps(record, indent=2))
cmdi = json.loads((root / 'cmdi/exit.json').read_text())
(root / 'combined_summary.json').write_text(json.dumps([cmdi, record], indent=2))
print(json.dumps(record), flush=True)
