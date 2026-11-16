"""Translate ELF function entries without importing angr or running CFG analysis."""
import faulthandler
import sys
import time
import archinfo
import pyvex
from elftools.elf.elffile import ELFFile

if '--no-faulthandler' not in sys.argv:
    faulthandler.enable()
if '--profile' in sys.argv:
    sys.setprofile(lambda *args: None)
if '--ctypes-lift' in sys.argv:
    from ctypes_lift_bridge import install
    install()
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
with open(target, 'rb') as handle:
    elf = ELFFile(handle)
    sections = [(s['sh_addr'], s.data()) for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_size']]
    symtab = elf.get_section_by_name('.symtab')
    addresses = {s['st_value'] for s in symtab.iter_symbols() if s['st_info']['type'] == 'STT_FUNC' and s['st_value']}
    readonly_regions = []
    for segment in elf.iter_segments():
        if segment['p_type'] == 'PT_LOAD' and segment['p_flags'] & 4 and not segment['p_flags'] & 2:
            readonly_regions.append((segment['p_vaddr'], segment.data().ljust(segment['p_memsz'], b'\0')))
    got = elf.get_section_by_name('.got')
    if got is not None:
        readonly_regions.append((got['sh_addr'], got.data()))

keepalive = []
if '--readonly' in sys.argv or '--register-only' in sys.argv or '--ctypes-register' in sys.argv:
    if '--ctypes-register' in sys.argv:
        import ctypes
        native = ctypes.CDLL(str(__import__('pathlib').Path(pyvex.__file__).parent / 'lib/libpyvex.so'))
        native.register_readonly_region.argtypes = [ctypes.c_uint64, ctypes.c_uint64, ctypes.c_void_p]
        native.register_readonly_region.restype = ctypes.c_ubyte
    for addr, content in readonly_regions:
        buf = pyvex.ffi.from_buffer(content)
        keepalive.append(buf)
        if '--ctypes-register' in sys.argv:
            native.register_readonly_region(addr, len(content), int(pyvex.ffi.cast('uintptr_t', buf)))
        else:
            pyvex.pvc.register_readonly_region(addr, len(content), buf)

arch = archinfo.ArchMIPS32(endness='Iend_LE')
started = time.monotonic()
count = 0
for repeat in range(3):
    for addr in sorted(addresses):
        for start, data in sections:
            offset = addr - start
            if not 0 <= offset < len(data):
                continue
            code = data[offset:offset + 400]
            for cross in (False, True):
                try:
                    block = pyvex.lift(code, addr, arch, max_bytes=len(code), opt_level=1, cross_insn_opt=cross, collect_data_refs='--no-data-refs' not in sys.argv, load_from_ro_regions='--readonly' in sys.argv)
                    count += 1
                except Exception:
                    print('FAILED', hex(addr), 'cross_insn_opt', cross, 'code', code.hex(), flush=True)
                    raise
            break
    print('PASS', repeat + 1, 'translations', count, 'elapsed', time.monotonic() - started, flush=True)
print('angr imported:', 'angr' in sys.modules)
