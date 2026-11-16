"""Translate once, then exercise conversion of an immutable native IR."""
import faulthandler
import sys
import pyvex
import pyvex.lifting.libvex as libvex
import archinfo

faulthandler.enable()
native = libvex.pvc
captured = []

class Proxy:
    def __getattr__(self, name):
        if name == 'vex_lift':
            def lift(*args):
                result = native.vex_lift(*args)
                captured[:] = [result]
                return result
            return lift
        return getattr(native, name)
    def __setattr__(self, name, value):
        setattr(native, name, value)

libvex.pvc = Proxy()
arch = archinfo.ArchAMD64()
code = bytes.fromhex('554889e54883ec10488b45084883c001488945f8c9c3')
initial = pyvex.lift(code, 0x400000, arch, collect_data_refs=True)
print('INITIAL LIFT COMPLETE', flush=True)
for repeat in range(5):
    for index in range(5000):
        block = pyvex.IRSB.empty_block(arch, 0x400000)
        block._from_c(captured[0])
    print('PASS', repeat + 1, flush=True)
