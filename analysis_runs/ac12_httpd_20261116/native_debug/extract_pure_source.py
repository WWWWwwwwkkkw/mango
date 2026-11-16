from pathlib import Path
import tarfile

root = Path(__file__).resolve().parent
destination = (root / 'pure_source').resolve()
with tarfile.open(root / 'pyvex-9.2.94.tar.gz') as archive:
    for member in archive.getmembers():
        prefix = 'pyvex-9.2.94/pyvex/'
        if member.isfile() and member.name.startswith(prefix) and member.name.endswith('.py'):
            relative = member.name[len('pyvex-9.2.94/'):]
            target = (destination / relative).resolve()
            if not target.is_relative_to(destination):
                raise ValueError('Invalid archive path')
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(archive.extractfile(member).read())
print(destination)
