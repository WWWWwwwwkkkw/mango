import json
import os
from pathlib import Path
import subprocess
import time

root = Path(__file__).resolve().parent.parent / 'current_run'
root.mkdir(exist_ok=True)
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
command = ['/root/myenv/bin/mango', target, '-c', 'intoverflow', '--results', str(root / 'results')]
env = dict(os.environ, PYTHONFAULTHANDLER='1', PYTHONUNBUFFERED='1')
env.pop('PYTHONPATH', None)
start = time.monotonic()
with (root / 'console.log').open('w') as output:
    process = subprocess.run(['/usr/bin/time', '-v', '-o', str(root / 'resources.txt'), *command],
                             cwd='/root/mango_0', env=env, stdout=output, stderr=subprocess.STDOUT)
result = dict(command=command, exit_code=process.returncode, elapsed=round(time.monotonic()-start, 3))
(root / 'exit.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result), flush=True)
