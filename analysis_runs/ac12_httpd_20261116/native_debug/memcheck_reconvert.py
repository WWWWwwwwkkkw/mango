import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parent
env = dict(os.environ, VALGRIND_LIB=str(root / 'toolroot/usr/libexec/valgrind'), PYTHONMALLOC='malloc')
with (root / 'memcheck_reconvert_console.log').open('w') as log:
    proc = subprocess.run([str(root / 'toolroot/usr/bin/valgrind'), '--tool=memcheck', '--leak-check=no',
        '--undef-value-errors=no', '--num-callers=30', '--error-exitcode=99', '--exit-on-first-error=yes',
        '--log-file=' + str(root / 'memcheck_reconvert_memory.log'), '/root/myenv/bin/python', str(root / 'reconvert.py')],
        env=env, stdout=log, stderr=subprocess.STDOUT, timeout=150)
print('exit', proc.returncode, flush=True)
