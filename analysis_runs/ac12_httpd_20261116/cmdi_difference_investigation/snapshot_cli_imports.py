import gc
import hashlib
import json
import logging
from pathlib import Path
import sys
import threading

import angr
import pyvex
from angr.analyses.cfg.cfg_fast import CFGFast
from pyvex.expr import IRExpr
from pyvex.stmt import IRStmt
import argument_resolver.analysis.mango as mango

root = Path(__file__).resolve().parent
label = sys.argv[1]
def state():
    functions = [angr.Project.__init__, CFGFast._mips_determine_function_gp, pyvex.IRSB._from_c, IRExpr._from_c, IRStmt._from_c]
    return {
        'recursion_limit':sys.getrecursionlimit(), 'gc_enabled':gc.isenabled(),'gc_threshold':gc.get_threshold(),
        'trace':repr(sys.gettrace()),'profile':repr(sys.getprofile()),'threads':[t.name for t in threading.enumerate()],
        'root_log_level':logging.getLogger().level,
        'function_bytecode':{f.__module__+'.'+f.__qualname__:hashlib.sha256(f.__code__.co_code).hexdigest() for f in functions},
        'lifters':{name:[f.__module__+'.'+f.__qualname__ for f in values] for name,values in pyvex.lifting.lifters.items()},
    }
before = state()
modules_before = set(sys.modules)
sys.argv = ['mango','/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd','-c','cmdi','--disable-progress','--results',str(root/'unused_results')]
args = mango.get_cli_args()
after = state()
from importlib import metadata
options = vars(args)
safe_options = {name:value for name,value in options.items() if not name.startswith(('llm_', 'int_')) and name != 'skip_llm'}
row={'label':label,'mango_path':mango.__file__,'before':before,'after':after,
     'additional_modules':sorted(set(sys.modules)-modules_before),'cmdi_options':safe_options}
(root/(label+'_cli_imports.json')).write_text(json.dumps(row,indent=2,default=str))
print(json.dumps({'label':label,'state_changed':before!=after,'extra_modules':len(row['additional_modules']),
                  'cmdi_options':safe_options},indent=2),flush=True)
