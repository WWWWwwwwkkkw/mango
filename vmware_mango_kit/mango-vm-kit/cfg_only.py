"""Independent CFG-only probe. Passing it does not imply full Mango completion."""
import faulthandler
import hashlib
import json
from pathlib import Path
import sys
import time
import angr

faulthandler.enable()
target = Path(sys.argv[1]).resolve()
print(json.dumps({'python': sys.version, 'executable': sys.executable,
                  'target': str(target), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}), flush=True)
project = angr.Project(str(target), auto_load_libs=False)
started = time.monotonic()
cfg = project.analyses.CFGFast(normalize=True, data_references=True, show_progressbar=False)
print(json.dumps({'cfg_passed': True, 'seconds': round(time.monotonic()-started, 3),
                  'functions': len(project.kb.functions), 'nodes': len(cfg.graph)}), flush=True)
