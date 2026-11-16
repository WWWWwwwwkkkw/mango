"""Extract an official CPython 3.11 wheel for isolated dependency comparison."""
import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

out = Path(__file__).resolve().parent
version = '2.0.0'
with urllib.request.urlopen(f'https://pypi.org/pypi/cffi/{version}/json', timeout=30) as response:
    metadata = json.load(response)
wheel = next(item for item in metadata['urls'] if 'cp311-cp311-manylinux2014_x86_64' in item['filename'])
with urllib.request.urlopen(wheel['url'], timeout=45) as response:
    data = response.read()
assert hashlib.sha256(data).hexdigest() == wheel['digests']['sha256']
(out / wheel['filename']).write_bytes(data)
dest = out / 'cffi2_overlay'
with zipfile.ZipFile(io.BytesIO(data)) as archive:
    for name in archive.namelist():
        path = Path(name)
        if '..' in path.parts or path.is_absolute():
            raise ValueError('Unexpected path')
    archive.extractall(dest)
print('OVERLAY_READY', dest, wheel['filename'], flush=True)
