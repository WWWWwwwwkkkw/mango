"""Run only CFGFast and record component paths and result sizes."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time
import angr
import pyvex

parser = argparse.ArgumentParser()
parser.add_argument('--no-data-refs', action='store_true')
parser.add_argument('--no-indirect', action='store_true')
args = parser.parse_args()
native = Path(pyvex.__file__).parent / 'lib/libpyvex.so'
print(json.dumps({'python': sys.version, 'angr': angr.__version__, 'pyvex': pyvex.__version__, 'native_path': str(native), 'native_sha256': hashlib.sha256(native.read_bytes()).hexdigest()}), flush=True)
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
project = angr.Project(target, auto_load_libs=False)
started = time.monotonic()
cfg = project.analyses.CFGFast(normalize=True, data_references=not args.no_data_refs, resolve_indirect_jumps=not args.no_indirect)
print(json.dumps({'status': 'complete', 'seconds': time.monotonic() - started, 'nodes': len(cfg.graph), 'functions': len(project.kb.functions)}), flush=True)
