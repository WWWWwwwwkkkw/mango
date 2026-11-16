"""Fetch exact Build-ID symbols from Ubuntu's public debuginfod service."""
from pathlib import Path
import re
import subprocess
import urllib.request

root = Path('/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/native_debug/toolroot/usr/lib/debug/.build-id')
for binary in ['/lib64/ld-linux-x86-64.so.2', '/lib/x86_64-linux-gnu/libc.so.6', '/usr/bin/python3.11']:
    build = re.search(r'Build ID: ([a-f0-9]+)', subprocess.check_output(['readelf', '-n', binary], text=True)).group(1)
    dest = root / build[:2] / (build[2:] + '.debug')
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_file() and dest.stat().st_size:
        print('CACHED', binary, build, dest.stat().st_size, flush=True)
        continue
    url = f'https://debuginfod.ubuntu.com/buildid/{build}/debuginfo'
    print('FETCH', binary, build, flush=True)
    try:
        with urllib.request.urlopen(url, timeout=50) as response:
            data = response.read()
        if data[:4] != b'\x7fELF':
            raise ValueError('Response is not ELF')
        dest.write_bytes(data)
        print('SAVED', len(data), dest, flush=True)
    except Exception as exc:
        print('FAILED', type(exc).__name__, str(exc), flush=True)
