import hashlib
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent
kit = root/'mango-vm-kit'
files = sorted(path for path in kit.iterdir() if path.is_file() and path.name != 'SHA256SUMS')
manifest = '\n'.join(hashlib.sha256(path.read_bytes()).hexdigest()+'  '+path.name for path in files)+'\n'
(kit/'SHA256SUMS').write_bytes(manifest.encode('ascii'))
archive_path = root/'mango-vm-kit.zip'
with zipfile.ZipFile(archive_path,'w',compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(kit.iterdir()):
        if path.is_file():
            archive.write(path,arcname='mango-vm-kit/'+path.name)
with zipfile.ZipFile(archive_path) as archive:
    assert archive.testzip() is None
print(str(archive_path))
print('bytes',archive_path.stat().st_size)
print('sha256',hashlib.sha256(archive_path.read_bytes()).hexdigest())
