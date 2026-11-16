"""Compare installed source and dependency payloads; no package code mutations."""
import ast
import difflib
import hashlib
import json
from pathlib import Path

out = Path(__file__).resolve().parent / 'cmdi_difference_investigation'
out.mkdir(exist_ok=True)
official = Path('/root/myenv_mango_official/lib/python3.11/site-packages')
extended = Path('/root/myenv_mango_extended/lib/python3.11/site-packages')

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

source = {'same': [], 'different': [], 'only_official': [], 'only_extended': []}
left_files = {str(path.relative_to(official / 'argument_resolver')): path for path in (official / 'argument_resolver').rglob('*.py')}
right_files = {str(path.relative_to(extended / 'argument_resolver')): path for path in (extended / 'argument_resolver').rglob('*.py')}
for name in sorted(set(left_files) | set(right_files)):
    if name not in left_files:
        source['only_extended'].append(name)
    elif name not in right_files:
        source['only_official'].append(name)
    elif sha(left_files[name]) == sha(right_files[name]):
        source['same'].append(name)
    else:
        source['different'].append(name)

name = 'analysis/mango.py'
diff = ''.join(difflib.unified_diff(left_files[name].read_text().splitlines(keepends=True),
                                  right_files[name].read_text().splitlines(keepends=True),
                                  fromfile='official/analysis/mango.py', tofile='extended/analysis/mango.py'))
(out / 'mango_cli.diff').write_text(diff)

def ast_digest(path, selected):
    tree = ast.parse(path.read_text())
    return {node.name: hashlib.sha256(ast.dump(node, include_attributes=False).encode()).hexdigest()
            for node in tree.body if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in selected}

ast_comparison = {
    name: {'official': ast_digest(left_files[name], selected), 'extended': ast_digest(right_files[name], selected)}
    for name, selected in [('analysis/mango.py', {'MangoAnalysis', 'main', 'get_cli_args'}), ('analysis/base.py', {'ScriptBase'})]
}

def payload_files(root):
    return {str(path.relative_to(root)): path for path in root.rglob('*')
            if path.is_file() and (path.suffix in {'.py', '.so'} or '.so.' in path.name)
            and path.relative_to(root).parts[0] != 'argument_resolver'}

left_payload, right_payload = payload_files(official), payload_files(extended)
payload = {'checked_common': 0, 'different': [], 'only_official': sorted(set(left_payload) - set(right_payload)),
           'only_extended': sorted(set(right_payload) - set(left_payload))}
for name in sorted(set(left_payload) & set(right_payload)):
    payload['checked_common'] += 1
    if sha(left_payload[name]) != sha(right_payload[name]):
        payload['different'].append(name)
report = {'mango_source_comparison': source, 'ast_comparison': ast_comparison, 'dependency_payload_comparison': payload}
(out / 'installed_comparison.json').write_text(json.dumps(report, indent=2))
print(json.dumps({'different_mango_files': source['different'], 'added_extension_files': source['only_extended'],
                  'dependency_payloads': payload, 'ast_comparison': ast_comparison}, indent=2), flush=True)
print(diff, flush=True)
