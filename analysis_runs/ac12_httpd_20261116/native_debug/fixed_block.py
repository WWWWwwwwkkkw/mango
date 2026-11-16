"""Repeated lifts of fixed bytes, independent of the firmware or ELF loader."""
import faulthandler
import gc
import sys
import pyvex
import archinfo

faulthandler.enable()
if '--no-gc' in sys.argv:
    gc.disable()
if '--x86' in sys.argv:
    arch = archinfo.ArchAMD64()
    code = bytes.fromhex('554889e54883ec10488b45084883c001488945f8c9c3')
else:
    arch = archinfo.ArchMIPS32(endness='Iend_LE')
    code = bytes.fromhex('10001c3cac089c2721e09903d8ffbd272400bfaf2000beaf21f0a0031000bcaf2800c4af2c00c5af1c00c0af21200000e880828f21c8400009f82003000000001000dc8f')
for repeat in range(5):
    for index in range(5000):
        block = pyvex.lift(code, 0x400000, arch, max_bytes=len(code), collect_data_refs=True)
    print('PASS', repeat + 1, flush=True)
