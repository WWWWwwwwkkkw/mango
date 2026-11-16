"""Compare complete CFFI field layouts with DWARF layouts in the shipped library."""
import json
import os
from pathlib import Path
import re
import subprocess
import pyvex

root = Path(__file__).resolve().parent
expected = {}
commands = ['set pagination off']
types = ['VexArchInfo', 'VEXLiftResult', 'IRSB', 'IRExpr', 'IRStmt', 'IRConst', 'IRTypeEnv']

def fields(type_, root_type, prefix='', base=0):
    for name, field in type_.fields:
        chain = prefix + name
        offset = base + field.offset
        key = root_type + '.' + chain
        expected[key] = offset
        commands.append(f'printf "{key}=%ld\\n", (long)&(({root_type}*)0)->{chain}')
        if field.type.kind in ('struct', 'union'):
            fields(field.type, root_type, chain + '.', offset)

for name in types:
    expected[name + '.sizeof'] = pyvex.ffi.sizeof(name)
    commands.append(f'printf "{name}.sizeof=%ld\\n", (long)sizeof({name})')
    fields(pyvex.ffi.typeof(name), name)

(root / 'layout_commands.gdb').write_text('\n'.join(commands) + '\n')
env = dict(os.environ, LD_LIBRARY_PATH=str(root / 'toolroot/usr/lib/x86_64-linux-gnu'))
gdb = str(root / 'toolroot/usr/bin/gdb')
native = Path(pyvex.__file__).parent / 'lib/libpyvex.so'
proc = subprocess.run([gdb, '-nx', '-nh', '--batch', str(native), '-x', str(root / 'layout_commands.gdb')], env=env, capture_output=True, text=True)
(root / 'native_layouts.log').write_text(proc.stdout + proc.stderr)
actual = {m.group(1): int(m.group(2)) for m in re.finditer(r'^([A-Za-z0-9_.]+)=(\d+)$', proc.stdout, re.M)}
differences = [{'field': key, 'cffi': val, 'native': actual.get(key)} for key, val in expected.items() if actual.get(key) != val]
result = {'native_library': str(native), 'checked': len(expected), 'gdb_exit': proc.returncode, 'differences': differences}
(root / 'layout_comparison.json').write_text(json.dumps(result, indent=2))
print(json.dumps(result, indent=2))
