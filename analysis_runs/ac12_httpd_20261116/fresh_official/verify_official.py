"""Verify the new upstream installation and test official sample plus original target."""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

root = Path(__file__).resolve().parent
venv = Path('/root/myenv_mango_official')
repo = Path('/root/mango_official')
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
env = dict(os.environ, PYTHONFAULTHANDLER='1', PYTHONUNBUFFERED='1', TERM='dumb')
for key in ['PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV']:
    env.pop(key, None)
records = []
cases = [
    ('official_simple', repo / 'package/tests/binaries/simple/program', 90),
    ('ac12_httpd', Path('/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'), 600),
]
for name, target, limit in cases:
    assert target.is_file(), target
    output = root / name
    output.mkdir(exist_ok=False)
    command = [str(venv / 'bin/mango'), str(target), '-c', 'cmdi', '--disable-progress', '--results', str(output / 'results')]
    print('START ' + name, flush=True)
    started = time.monotonic()
    timed_out = False
    with (output / 'console.log').open('w') as log:
        process = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(output / 'resources.txt'), *command],
                                   cwd=repo, env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            process.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            timed_out = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()
    files = [str(path.relative_to(output)) for path in output.rglob('*.json')]
    record = dict(case=name, target=str(target), command=command, exit_code=process.returncode,
                  seconds=round(time.monotonic() - started, 3), timed_out=timed_out, json_files=files)
    (output / 'exit.json').write_text(json.dumps(record, indent=2))
    records.append(record)
    (root / 'verification_summary.json').write_text(json.dumps(records, indent=2))
    print(json.dumps(record), flush=True)
print('VERIFICATION RUNS FINISHED', flush=True)
