"""Reproduce the initial CFG failure without changing the installed analyzer."""
import sys
import faulthandler
import traceback
import angr

faulthandler.enable()
faulthandler.dump_traceback_later(45, repeat=True)

target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
print('Python:', sys.version, flush=True)
print('angr:', angr.__version__, angr.__file__, flush=True)
project = angr.Project(target, auto_load_libs=False)
print('Architecture:', project.arch, flush=True)
try:
    cfg = project.analyses.CFGFast(normalize=True, data_references=True, show_progressbar='--progress' in sys.argv)
except Exception:
    traceback.print_exc()
    sys.exit(1)
print('CFGFast succeeded:', len(cfg.graph), 'nodes;', len(project.kb.functions), 'functions')
