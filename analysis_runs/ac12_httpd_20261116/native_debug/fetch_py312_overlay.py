import hashlib
import io
import json
from pathlib import Path
import urllib.request
import zipfile

root = Path(__file__).resolve().parent
dest = root / 'py312_overlay'
for name, version in [('cffi', '1.17.1'), ('bitarray', '2.9.3')]:
    with urllib.request.urlopen(f'https://pypi.org/pypi/{name}/{version}/json', timeout=30) as response:
        metadata = json.load(response)
    wheel = next(x for x in metadata['urls'] if 'cp312-cp312-' in x['filename'] and 'manylinux' in x['filename'] and 'x86_64' in x['filename'])
    with urllib.request.urlopen(wheel['url'], timeout=45) as response:
        data = response.read()
    assert hashlib.sha256(data).hexdigest() == wheel['digests']['sha256']
    (root / wheel['filename']).write_bytes(data)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for item in archive.namelist():
            if Path(item).is_absolute() or '..' in Path(item).parts:
                raise ValueError('Unexpected wheel path')
        archive.extractall(dest)
    print('EXTRACTED', wheel['filename'], flush=True)
