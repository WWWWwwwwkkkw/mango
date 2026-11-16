import json
from pathlib import Path
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
inventory = json.loads((root / 'inventory.json').read_text())
links = []
for item in inventory['venvs']:
    directory = Path(item['root']) / 'bin'
    row = {'root': item['root'], 'python_links': [], 'library_dirs': []}
    for name in ['python', 'python3', 'python3.11', 'python3.12']:
        path = directory / name
        if path.exists() or path.is_symlink():
            row['python_links'].append({'name': name, 'symlink': path.readlink().as_posix() if path.is_symlink() else None,
                                         'resolved': str(path.resolve())})
    library = Path(item['root']) / 'lib'
    if library.exists():
        row['library_dirs'] = [path.name for path in library.glob('python*') if path.is_dir()]
    links.append(row)
startup = []
for name in ['python3.11', 'python3.12']:
    path = Path('/usr/lib') / name / 'sitecustomize.py'
    if path.is_file():
        startup.append({'path': str(path), 'resolved': str(path.resolve()), 'text': path.read_text()})
(root / 'interpreter_links.json').write_text(json.dumps({'venvs': links, 'system_sitecustomize': startup}, indent=2))
print(json.dumps(links, indent=2))
