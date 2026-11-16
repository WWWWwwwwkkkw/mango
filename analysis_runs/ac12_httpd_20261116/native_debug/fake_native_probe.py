"""Load only PyVEX's Python converters and CFFI type declarations. No libpyvex."""
import json
from pathlib import Path
import runpy
import sys
import types

root = Path(__file__).resolve().parent
package_path = Path('/root/myenv/lib/python3.11/site-packages/pyvex')
if '--local-source' in sys.argv:
    package_path = root / 'pure_source' / 'pyvex'
package = types.ModuleType('pyvex')
package.__path__ = [str(package_path)]
package.__file__ = str(package_path / '__init__.py')
sys.modules['pyvex'] = package
native = types.ModuleType('pyvex.native')
if '--pure-python' in sys.argv:
    class Struct:
        def __getattr__(self, name):
            value = Struct()
            setattr(self, name, value)
            return value
        def __getitem__(self, index):
            return self
    class FakeFFI:
        NULL = object()
        def new(self, declaration): return Struct()
    native.ffi = FakeFFI()
else:
    import cffi
    native.ffi = cffi.FFI()
    declarations = runpy.run_path(str(package_path / 'vex_ffi.py'))['ffi_str']
    native.ffi.cdef(declarations)

class Constants:
    def __init__(self):
        self.__dict__.update(json.loads((root / 'native_constants.json').read_text()))
    def __getattr__(self, name):
        return lambda *args: 0

native.pvc = Constants()
sys.modules['pyvex.native'] = native
package.ffi, package.pvc = native.ffi, native.pvc
maps = Path('/proc/self/maps').read_text() if sys.platform != 'win32' else ''
print('Native library mapped:', 'libpyvex' in maps, 'CFFI mapped:', '_cffi_backend' in maps, flush=True)
sys.argv = [str(root / 'conversion_only.py')]
runpy.run_path(str(root / 'conversion_only.py'), run_name='__main__')
