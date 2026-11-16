"""Check installed package payloads against their wheel RECORD hashes."""
from importlib import metadata
import base64
import hashlib
import json

results = []
for name in ['angr', 'pyvex', 'cle', 'claripy', 'archinfo', 'cffi', 'capstone', 'unicorn', 'z3-solver']:
    dist = metadata.distribution(name)
    checked = 0
    mismatches = []
    for file in dist.files or []:
        if file.hash is None or str(file).endswith('.pyc'):
            continue
        path = dist.locate_file(file)
        if not path.is_file():
            mismatches.append({'file': str(file), 'error': 'missing'})
            continue
        digest = hashlib.new(file.hash.mode, path.read_bytes()).digest()
        actual = base64.urlsafe_b64encode(digest).decode().rstrip('=')
        checked += 1
        if actual != file.hash.value:
            mismatches.append({'file': str(file), 'error': 'hash_mismatch'})
    results.append({'package': name, 'version': dist.version, 'checked': checked, 'mismatches': mismatches})
print(json.dumps(results, indent=2))
