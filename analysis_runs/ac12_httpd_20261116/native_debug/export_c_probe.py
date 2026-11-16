from pathlib import Path
import struct
from elftools.elf.elffile import ELFFile

out = Path(__file__).resolve().parent
target = '/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd'
with open(target, 'rb') as handle:
    elf = ELFFile(handle)
    sections = [(s['sh_addr'], s.data()) for s in elf.iter_sections() if s['sh_flags'] & 4 and s['sh_size']]
    addresses = {s['st_value'] for s in elf.get_section_by_name('.symtab').iter_symbols() if s['st_info']['type'] == 'STT_FUNC' and s['st_value']}
    regions = [(p['p_vaddr'], p.data().ljust(p['p_memsz'], b'\0')) for p in elf.iter_segments() if p['p_type'] == 'PT_LOAD' and p['p_flags'] & 4 and not p['p_flags'] & 2]
    got = elf.get_section_by_name('.got')
    regions.append((got['sh_addr'], got.data()))
blocks = []
for addr in sorted(addresses):
    for start, data in sections:
        offset = addr - start
        if 0 <= offset < len(data):
            blocks.append((addr, data[offset:offset + 400]))
            break
with (out / 'c_probe_inputs.bin').open('wb') as handle:
    handle.write(struct.pack('<II', len(regions), len(blocks)))
    for addr, data in regions + blocks:
        handle.write(struct.pack('<QI', addr, len(data)))
        handle.write(data)
print('regions:', len(regions), 'blocks:', len(blocks))
