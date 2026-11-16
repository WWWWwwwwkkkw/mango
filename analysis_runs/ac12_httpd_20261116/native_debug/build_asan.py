"""Build the exact released C library with ASan in an isolated temporary tree."""
from pathlib import Path
import shutil
import subprocess
import tarfile

out = Path('/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/native_debug')
build = Path('/tmp/mango_pyvex_asan_20261116')
build.mkdir(exist_ok=True)
with tarfile.open(out / 'pyvex-9.2.94.tar.gz') as archive:
    archive.extractall(build, filter='data')
source = build / 'pyvex-9.2.94'
print('Building in', source, flush=True)
flags = '-g -O1 -fsanitize=address -fno-omit-frame-pointer'
subprocess.run(['make', '-f', 'Makefile-gcc', 'MULTIARCH=1', 'DEBUG=1', 'EXTRA_CFLAGS=' + flags], cwd=source / 'vex', check=True)
subprocess.run(['make', 'VEX_INCLUDE_PATH=' + str(source / 'vex/pub'), 'VEX_LIB_PATH=' + str(source / 'vex'), 'CFLAGS=' + flags + ' -Wall -shared -fPIC -std=c99 -I' + str(source / 'vex/pub')], cwd=source / 'pyvex_c', check=True)
overlay = out / 'asan_overlay'
shutil.copytree('/root/myenv/lib/python3.11/site-packages/pyvex', overlay / 'pyvex', ignore=shutil.ignore_patterns('*.so', '*.a', '__pycache__'), dirs_exist_ok=True)
(overlay / 'pyvex/lib').mkdir(exist_ok=True)
shutil.copy2(source / 'pyvex_c/libpyvex.so', overlay / 'pyvex/lib/libpyvex.so')
print('ASAN_READY', overlay, flush=True)
shutil.copytree(source / 'vex/pub', out / 'source/vex/pub', dirs_exist_ok=True)
shutil.copytree(source / 'vex/priv', out / 'source/vex/priv', ignore=shutil.ignore_patterns('*.o'), dirs_exist_ok=True)
