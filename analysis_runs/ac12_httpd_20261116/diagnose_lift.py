"""Capture the last VEX translation request for a native-crash reproducer."""
import faulthandler
import json
from pathlib import Path
import sys
import angr
from angr.engines.vex.lifter import VEXLifter

faulthandler.enable()
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
out = Path('/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116')
original = VEXLifter.lift_vex
log = (out / 'lift_requests.jsonl').open('w', buffering=1)

def traced_lift(self, *args, **kwargs):
    entry = {'positional': [str(x)[:100] for x in args], 'kwargs': {k: v if isinstance(v, (int, str, bool, type(None))) else str(type(v)) for k, v in kwargs.items()}}
    log.write(json.dumps(entry) + '\n')
    return original(self, *args, **kwargs)

VEXLifter.lift_vex = traced_lift
project = angr.Project(target, auto_load_libs=False)
try:
    cfg = project.analyses.CFGFast(normalize=True, data_references=True)
except Exception:
    import traceback
    traceback.print_exc()
    sys.exit(1)
print('CFG succeeded:', len(cfg.graph), len(project.kb.functions))
