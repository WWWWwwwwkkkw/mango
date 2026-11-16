"""Compare cached code objects to source compilation, without executing cached code."""
import hashlib
import importlib.util
import json
import marshal
from pathlib import Path
import struct
import types

site = Path('/root/myenv/lib/python3.11/site-packages')
out = Path(__file__).resolve().parent
results = []
checked = 0

def differences(old, new, trail='<module>'):
    changes = []
    attrs = ('co_code', '_co_code_adaptive', 'co_linetable', 'co_firstlineno', 'co_name', 'co_qualname', 'co_names', 'co_varnames', 'co_freevars', 'co_cellvars', 'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals', 'co_stacksize', 'co_flags', 'co_exceptiontable')
    changed = [name for name in attrs if getattr(old, name) != getattr(new, name)]
    if changed:
        changes.append({'code': trail, 'changed': changed, 'cached_code_hex': old.co_code.hex() if 'co_code' in changed else None, 'fresh_code_hex': new.co_code.hex() if 'co_code' in changed else None})
    if len(old.co_consts) != len(new.co_consts):
        changes.append({'code': trail, 'changed': ['co_consts_length'], 'cached_length': len(old.co_consts), 'fresh_length': len(new.co_consts)})
    for i, (a, b) in enumerate(zip(old.co_consts, new.co_consts)):
        if isinstance(a, types.CodeType) and isinstance(b, types.CodeType):
            changes.extend(differences(a, b, trail + '.' + b.co_name))
        elif isinstance(a, types.CodeType) != isinstance(b, types.CodeType) or a != b:
            changes.append({'code': trail, 'changed': ['co_consts'], 'index': i, 'cached_type': type(a).__name__, 'fresh_type': type(b).__name__})
    return changes

roots = [site / package for package in ['pyvex', 'archinfo', 'cffi', 'bitstring', 'angr', 'claripy', 'cle', 'bitarray', 'pycparser', 'sortedcontainers', 'packaging']]
roots.append(Path('/usr/lib/python3.11'))
for directory in roots:
    for source in directory.rglob('*.py'):
        cache = source.parent / '__pycache__' / (source.stem + '.cpython-311.pyc')
        if not cache.is_file():
            continue
        raw = cache.read_bytes()
        if raw[:4] != importlib.util.MAGIC_NUMBER:
            results.append({'source': str(source), 'cache': str(cache), 'error': 'magic_mismatch'})
            continue
        try:
            old = marshal.loads(raw[16:])
            fresh = compile(source.read_bytes(), str(source), 'exec', dont_inherit=True, optimize=0)
            changed = differences(old, fresh)
            checked += 1
            if changed:
                results.append({'source': str(source), 'cache': str(cache), 'cache_sha256': hashlib.sha256(raw).hexdigest(), 'flags': struct.unpack('<I', raw[4:8])[0], 'changes': changed})
        except Exception as exc:
            results.append({'source': str(source), 'cache': str(cache), 'error': type(exc).__name__})
summary = {'checked': checked, 'mismatched_files': len(results), 'details': results}
(out / 'bytecode_audit.json').write_text(json.dumps(summary, indent=2))
print('checked', checked, 'mismatched_files', len(results))
for item in results:
    print(item['source'], item.get('error') or len(item['changes']))
