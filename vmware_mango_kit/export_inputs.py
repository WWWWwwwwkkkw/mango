"""Export requested local input/code for the user's VMware comparison; no uploads."""
import hashlib
from pathlib import Path
import shutil
import tarfile

kit = Path('/mnt/c/Users/ROG/Desktop/mango_0/vmware_mango_kit/mango-vm-kit')
kit.mkdir(parents=True, exist_ok=True)
workspace = Path('/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116')
target = Path('/root/AC12/_US_AC1206V1.0RTL_V15.03.06.23_multi_TD01.bin.extracted/squashfs-root/bin/httpd')
source = Path('/root/mango_0')
shutil.copyfile(target, kit/'httpd')
assert hashlib.sha256((kit/'httpd').read_bytes()).hexdigest() == '5c6330ab898620f25009d1dc5fa4046e2ca7c3beacf3cdbbf9b12a4e028b5661'
shutil.copyfile(workspace/'native_debug/python_runtime_repro.py', kit/'runtime_repro.py')
shutil.copyfile(workspace/'fresh_extended/dependencies.lock.txt', kit/'requirements-baseline.lock')

def keep(member):
    parts = Path(member.name).parts
    if '__pycache__' in parts or any(part.endswith('.egg-info') for part in parts) or member.name.endswith(('.pyc','.pyo')):
        return None
    return member

with tarfile.open(kit/'mango_0_source.tar.gz', 'w:gz') as archive:
    for relative in ['README.md', 'pyproject.toml', 'package/argument_resolver', 'package/py.typed']:
        path = source/relative
        if path.exists():
            archive.add(path, arcname='mango_0/'+relative, filter=keep)
with tarfile.open(kit/'mango_0_source.tar.gz') as archive:
    for member in archive.getmembers():
        if not member.name.startswith('mango_0/') or member.name.startswith('/') or '..' in Path(member.name).parts:
            raise ValueError('Unexpected archive path')
print('Exported httpd, current extension source, dependency lock, and runtime reproducer.')
