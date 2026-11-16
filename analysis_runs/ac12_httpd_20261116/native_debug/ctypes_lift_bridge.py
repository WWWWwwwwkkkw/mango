"""Diagnostic replacement of only the libffi call boundary for vex_lift."""
import ctypes
from pathlib import Path
import pyvex
import pyvex.lifting.libvex as implementation

def install():
    original = implementation.pvc
    library = ctypes.CDLL(str(Path(pyvex.__file__).parent / 'lib/libpyvex.so'))
    class ArchInfo(ctypes.Structure):
        _fields_ = [('words', ctypes.c_uint64 * 7)]
    call = library.vex_lift
    call.argtypes = [ctypes.c_int, ArchInfo, ctypes.c_void_p, ctypes.c_uint64, ctypes.c_uint, ctypes.c_uint, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_uint]
    call.restype = ctypes.c_void_p

    def lift(arch, archinfo, data, addr, max_inst, max_bytes, opt, trace, allow, strict, collect, px, lookback):
        info = pyvex.ffi.new('VexArchInfo *', archinfo)
        copied = ArchInfo.from_buffer_copy(bytes(pyvex.ffi.buffer(info, pyvex.ffi.sizeof('VexArchInfo'))))
        pointer = int(pyvex.ffi.cast('uintptr_t', data))
        result = call(arch, copied, pointer, addr, max_inst, max_bytes, opt, trace, allow, strict, collect, px, lookback)
        return pyvex.ffi.cast('VEXLiftResult *', result or 0)

    class Proxy:
        def __getattr__(self, name):
            return lift if name == 'vex_lift' else getattr(original, name)
        def __setattr__(self, name, value):
            setattr(original, name, value)
    implementation.pvc = Proxy()
