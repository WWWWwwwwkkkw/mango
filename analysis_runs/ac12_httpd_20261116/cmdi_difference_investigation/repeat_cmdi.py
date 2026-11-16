"""Repeat unchanged CLI calls; stop after the log proves CFG/VRA completed."""
import json
import os
from pathlib import Path
import resource
import signal
import subprocess
import time

root = Path(__file__).resolve().parent
output = root / ('repeats_' + str(int(time.time())))
output.mkdir()
resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
env = dict(os.environ, PYTHONFAULTHANDLER='1', PYTHONUNBUFFERED='1', TERM='dumb', COLUMNS='120')
for key in ['PYTHONPATH', 'PYTHONHOME', 'VIRTUAL_ENV']:
    env.pop(key, None)
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
records = []
print('OUTPUT ' + str(output), flush=True)
for trial in range(1, 3):
    for flavor, venv in [('official', '/root/myenv_mango_official'), ('extended', '/root/myenv_mango_extended')]:
        directory = output / f'{flavor}_{trial}'
        directory.mkdir()
        command = [venv + '/bin/mango', target, '-c', 'cmdi', '--disable-progress', '--results', str(directory / 'results')]
        started = time.monotonic()
        stopped_after_initialization = False
        timed_out = False
        print('START', flavor, trial, flush=True)
        with (directory / 'console.log').open('w') as log:
            process = subprocess.Popen(['/usr/bin/time', '-v', '-o', str(directory / 'resources.txt'), *command],
                                       cwd='/root/mango_official' if flavor == 'official' else '/root/mango_0',
                                       env=env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            while process.poll() is None:
                time.sleep(2)
                content = (directory / 'console.log').read_text(errors='replace')
                if 'TARGETING SINKS:' in content:
                    stopped_after_initialization = True
                    break
                if time.monotonic() - started > 300:
                    timed_out = True
                    break
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
        content = (directory / 'console.log').read_text(errors='replace')
        row = {'flavor': flavor, 'trial': trial, 'command': command, 'exit_code': process.returncode,
               'seconds': round(time.monotonic() - started, 3), 'timed_out': timed_out,
               'intentionally_stopped_after_initialization': stopped_after_initialization,
               'cfg_and_vra_completed': 'TARGETING SINKS:' in content,
               'segfault': process.returncode in [-11, 139] or 'Fatal Python error: Segmentation fault' in content}
        (directory / 'exit.json').write_text(json.dumps(row, indent=2))
        records.append(row)
        (output / 'summary.json').write_text(json.dumps(records, indent=2))
        print(json.dumps(row), flush=True)
print('DONE', flush=True)
