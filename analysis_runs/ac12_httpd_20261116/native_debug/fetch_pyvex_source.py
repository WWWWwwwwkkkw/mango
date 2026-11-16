"""Download the exact PyPI source release and copy only C/header source files."""
import io
import json
from pathlib import Path
import tarfile
import urllib.request

root = Path('/mnt/c/Users/ROG/Desktop/mango_0/analysis_runs/ac12_httpd_20261116/native_debug')
with urllib.request.urlopen('https://pypi.org/pypi/pyvex/9.2.94/json', timeout=40) as response:
    metadata = json.load(response)
record = next(item for item in metadata['urls'] if item['packagetype'] == 'sdist')
print('Source release:', record['url'], 'bytes:', record['size'], flush=True)
with urllib.request.urlopen(record['url'], timeout=60) as response:
    data = response.read()
(root / record['filename']).write_bytes(data)
with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
    for member in archive.getmembers():
        parts = Path(member.name).parts
        if not member.isfile() or len(parts) < 3 or parts[1] != 'pyvex_c' or not member.name.endswith(('.c', '.h')):
            continue
        relative = Path(*parts[1:])
        if '..' in relative.parts or relative.is_absolute():
            raise ValueError('Unexpected archive path')
        dest = root / 'source' / relative
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(archive.extractfile(member).read())
print('C source extracted to', root / 'source', flush=True)
